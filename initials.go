package pdfsign

import (
	"bytes"
	"fmt"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/initials"
	"github.com/digitorus/pdfsign/internal/render"
	"github.com/digitorus/pdfsign/sign"
)

// AddInitials adds initials to all pages.
func (d *Document) AddInitials(appearance *Appearance) *initials.Builder {
	config := &initials.Config{
		Appearance: appearance.RenderInfo(),
	}
	d.pendingInitials = config
	return &initials.Builder{Config: config}
}

// applyInitials generates updates to add initials to the document.
func (d *Document) applyInitials(sb *SignBuilder) func(context *sign.SignContext) error {
	if d.pendingInitials == nil {
		return nil
	}
	config := d.pendingInitials

	return func(context *sign.SignContext) error {
		// 1. Create Appearance Stream
		rect := [4]float64{0, 0, config.Appearance.Width, config.Appearance.Height}
		renderer := render.NewAppearanceRenderer(
			config.Appearance,
			sb.signerName,
			sb.reason,
			sb.location,
		)

		appStream, err := renderer(context, rect)
		if err != nil {
			return fmt.Errorf("failed to render initials appearance: %w", err)
		}

		appObjID, err := context.AddObject(appStream)
		if err != nil {
			return fmt.Errorf("failed to add initials appearance object: %w", err)
		}

		// 2. Iterate pages
		numPages := context.PDFReader.NumPage()
		for i := 1; i <= numPages; i++ {
			// Check exclusions
			excluded := false
			for _, p := range config.ExcludePages {
				if p == i {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}

			pageObj, err := d.findPage(i)
			if err != nil {
				return err
			}

			// Calculate position
			mediaBox := pageObj.Key("MediaBox")
			mb := [4]float64{0, 0, 612, 792} // Default Letter
			if mediaBox.Kind() == pdf.Array && mediaBox.Len() >= 4 {
				mb[0] = mediaBox.Index(0).Float64()
				mb[1] = mediaBox.Index(1).Float64()
				mb[2] = mediaBox.Index(2).Float64()
				mb[3] = mediaBox.Index(3).Float64()
			}

			annotW := config.Appearance.Width
			annotH := config.Appearance.Height

			var x, y float64
			switch initials.Position(config.Position) {
			case initials.TopLeft:
				x = mb[0] + config.MarginX
				y = mb[3] - config.MarginY - annotH
			case initials.TopRight:
				x = mb[2] - config.MarginX - annotW
				y = mb[3] - config.MarginY - annotH
			case initials.BottomLeft:
				x = mb[0] + config.MarginX
				y = mb[1] + config.MarginY
			case initials.BottomRight:
				x = mb[2] - config.MarginX - annotW
				y = mb[1] + config.MarginY
			}

			// Create Annotation Object
			var annotBuf bytes.Buffer
			annotBuf.WriteString("<<\n")
			annotBuf.WriteString("  /Type /Annot\n")
			annotBuf.WriteString("  /Subtype /Widget\n")
			fmt.Fprintf(&annotBuf, "  /Rect [%.2f %.2f %.2f %.2f]\n", x, y, x+annotW, y+annotH)
			annotBuf.WriteString("  /F 4\n")
			fmt.Fprintf(&annotBuf, "  /AP << /N %d 0 R >>\n", appObjID)
			ptr := pageObj.GetPtr()
			annotBuf.WriteString("  /P " + fmt.Sprintf("%d %d R", ptr.GetID(), ptr.GetGen()) + "\n")
			annotBuf.WriteString(">>")

			annotObjID, err := context.AddObject(annotBuf.Bytes())
			if err != nil {
				return err
			}

			// Check if this page is the one receiving the signature
			// sb.appPage is 1-based index (default 1)
			if sb.appPage == i {
				// REGISTER FOR LATER: Do NOT add directly, as Sign will overwrite this page.
				// We add it to the ExtraAnnots map in context.
				if context.ExtraAnnots == nil {
					context.ExtraAnnots = make(map[uint32][]uint32)
				}
				pageID := ptr.GetID()
				context.ExtraAnnots[pageID] = append(context.ExtraAnnots[pageID], annotObjID)

				// Important: We perform the standard addAnnotToPage for NON-signature pages,
				// but for the signature page, we rely on createIncPageUpdate to pick up this annot.
				continue
			}

			if err := d.addAnnotToPage(context, pageObj, annotObjID); err != nil {
				return err
			}
		}

		return nil
	}
}

func (d *Document) findPage(pageNum int) (pdf.Value, error) {
	root := d.rdr.Trailer().Key("Root")
	pages := root.Key("Pages")
	p, _, err := d.findPageRec(pages, pageNum)
	return p, err
}

func (d *Document) findPageRec(node pdf.Value, pageNum int) (pdf.Value, int, error) {
	nodeType := node.Key("Type").Name()
	if nodeType == "Page" {
		if pageNum == 1 {
			return node, 0, nil
		}
		return pdf.Value{}, pageNum - 1, nil
	}

	if nodeType == "Pages" {
		kids := node.Key("Kids")
		if kids.Kind() == pdf.Array {
			for i := 0; i < kids.Len(); i++ {
				p, n, err := d.findPageRec(kids.Index(i), pageNum)
				if err != nil {
					return pdf.Value{}, 0, err
				}
				if p.Kind() != 0 {
					return p, 0, nil
				}
				pageNum = n
			}
		}
	}
	return pdf.Value{}, pageNum, nil
}

func (d *Document) addAnnotToPage(context *sign.SignContext, page pdf.Value, annotID uint32) error {
	var buf bytes.Buffer
	buf.WriteString("<<\n")

	for _, key := range page.Keys() {
		if key == "Annots" {
			continue
		}
		// Skip Type, we will force it to be /Page
		if key == "Type" {
			continue
		}

		val := page.Key(key)
		fmt.Fprintf(&buf, "  /%s ", key)

		if val.Kind() == pdf.Array {
			buf.WriteString("[")
			for i := 0; i < val.Len(); i++ {
				v := val.Index(i)
				ptr := v.GetPtr()
				if ptr.GetID() > 0 {
					fmt.Fprintf(&buf, " %d %d R", ptr.GetID(), ptr.GetGen())
				} else {
					fmt.Fprintf(&buf, " %v", v.Float64())
				}
			}
			buf.WriteString(" ]\n")
		} else {
			ptr := val.GetPtr()
			if ptr.GetID() > 0 {
				fmt.Fprintf(&buf, "%d %d R\n", ptr.GetID(), ptr.GetGen())
			} else {
				str := val.String()
				if val.Kind() == pdf.Name {
					str = "/" + val.Name()
				}
				buf.WriteString(str + "\n")
			}
		}
	}

	// Always ensure /Type /Page is present and direct
	buf.WriteString("  /Type /Page\n")

	// Add Annots
	buf.WriteString("  /Annots [")
	annots := page.Key("Annots")
	if annots.Kind() == pdf.Array {
		for i := 0; i < annots.Len(); i++ {
			ptr := annots.Index(i).GetPtr()
			if ptr.GetID() > 0 {
				fmt.Fprintf(&buf, " %d %d R", ptr.GetID(), ptr.GetGen())
			}
		}
	} else if annots.Kind() != 0 {
		ptr := annots.GetPtr()
		if ptr.GetID() > 0 {
			fmt.Fprintf(&buf, " %d %d R", ptr.GetID(), ptr.GetGen())
		}
	}
	fmt.Fprintf(&buf, " %d 0 R", annotID)
	buf.WriteString(" ]\n")

	buf.WriteString(">>")

	ptr := page.GetPtr()
	return context.UpdateObject(ptr.GetID(), buf.Bytes())
}
