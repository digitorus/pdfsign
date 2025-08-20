package sign

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
)

// fillInitialsFields will search the AcroForm Fields array for fields with names
// matching the pattern `initials_page_${pageIndex}_signer_${signer_uid}` and,
// when the signer_uid matches the configured Appearance.SignerUID, replace the
// field value (/V) with the initials computed from SignData.Signature.Info.Name.
func (context *SignContext) fillInitialsFields() error {
	uid := context.SignData.Appearance.SignerUID
	if uid == "" {
		return nil
	}

	name := context.SignData.Signature.Info.Name
	if name == "" {
		return nil
	}

	// compute initials (first rune of each name part, uppercased)
	parts := strings.Fields(name)
	var initialsRunes []rune
	for _, p := range parts {
		r := []rune(p)
		if len(r) > 0 {
			initialsRunes = append(initialsRunes, unicode.ToUpper(r[0]))
		}
	}
	initials := string(initialsRunes)

	acroForm := context.PDFReader.Trailer().Key("Root").Key("AcroForm")
	if acroForm.IsNull() {
		return nil
	}

	fields := acroForm.Key("Fields")
	if fields.IsNull() {
		return nil
	}

	// Match the pattern anywhere in the field name to tolerate BOM or encoding prefixes
	pattern := `initials_page_(\d+)_signer_(.+)`
	re := regexp.MustCompile(pattern)

	for i := 0; i < fields.Len(); i++ {
		field := fields.Index(i)
		t := field.Key("T")
		if t.IsNull() {
			continue
		}

		fieldName := t.RawString()
		// If the field name is UTF-16 with a BOM, decode it to UTF-8 for regex matching.
		decodedFieldName := fieldName
		b := []byte(fieldName)
		if len(b) >= 2 {
			// BOM 0xFEFF = big endian, 0xFFFE = little endian
			if b[0] == 0xfe && b[1] == 0xff {
				// UTF-16 BE
				var u16s []uint16
				for i := 2; i+1 < len(b); i += 2 {
					u16s = append(u16s, uint16(b[i])<<8|uint16(b[i+1]))
				}
				decodedFieldName = string(utf16.Decode(u16s))
			} else if b[0] == 0xff && b[1] == 0xfe {
				// UTF-16 LE
				var u16s []uint16
				for i := 2; i+1 < len(b); i += 2 {
					u16s = append(u16s, uint16(b[i])|uint16(b[i+1])<<8)
				}
				decodedFieldName = string(utf16.Decode(u16s))
			}
		}
		matches := re.FindStringSubmatch(decodedFieldName)
		var fieldSigner string
		if len(matches) >= 3 {
			fieldSigner = matches[2]
		} else {
			// Fallback: try to find 'signer_' in the field name and extract a hex-like tail.
			if idx := strings.Index(decodedFieldName, "signer_"); idx >= 0 {
				tail := decodedFieldName[idx+len("signer_"):]
				// Extract hex substring from tail
				hexRe := regexp.MustCompile(`[0-9a-fA-F]+`)
				hs := hexRe.FindString(tail)
				if hs == "" {
					continue
				}
				fieldSigner = hs
			} else {
				continue
			}
		}

		// Compare configured uid with the field signer. The fieldSigner may
		// be hex-encoded; accept either exact match, hex(uid), or hex-decoded match.
		matched := false
		if fieldSigner == uid {
			matched = true
		} else if hex.EncodeToString([]byte(uid)) == fieldSigner {
			matched = true
		} else {
			// try decoding fieldSigner as hex
			if bs, err := hex.DecodeString(fieldSigner); err == nil {
				if string(bs) == uid {
					matched = true
				}
			}
		}

		if !matched {
			continue
		}

		// Attempt to update the parent field object if it's indirect.
		ptr := field.GetPtr()
		if ptr.GetID() == 0 {
		} else {

			// Build a new dictionary preserving existing keys except /V which we replace
			var buf bytes.Buffer
			buf.WriteString("<<\n")
			for _, key := range field.Keys() {
				if key == "V" {
					continue
				}
				buf.WriteString(" /")
				buf.WriteString(key)
				buf.WriteString(" ")
				context.serializeCatalogEntry(&buf, ptr.GetID(), field.Key(key))
				buf.WriteString("\n")
			}

			// Set new value
			buf.WriteString(" /V ")
			buf.WriteString(pdfString(initials))
			buf.WriteString("\n")
			buf.WriteString(">>\n")

			if err := context.updateObject(uint32(ptr.GetID()), buf.Bytes()); err != nil {
				return fmt.Errorf("failed to update field object %d: %w", ptr.GetID(), err)
			}
		}

		// Also try to update any Kids (widget annotations) so visible widget values
		// reflect the new value. Kids can be indirect references and should be
		// updated even when the parent field is a direct object.
		kids := field.Key("Kids")
		if !kids.IsNull() {
			for k := 0; k < kids.Len(); k++ {
				kid := kids.Index(k)
				kptr := kid.GetPtr()
				if kptr.GetID() == 0 {
					continue
				}

				var kbuf bytes.Buffer
				kbuf.WriteString("<<\n")
				for _, kkey := range kid.Keys() {
					if kkey == "V" {
						continue
					}
					kbuf.WriteString(" /")
					kbuf.WriteString(kkey)
					kbuf.WriteString(" ")
					context.serializeCatalogEntry(&kbuf, kptr.GetID(), kid.Key(kkey))
					kbuf.WriteString("\n")
				}
				kbuf.WriteString(" /V ")
				kbuf.WriteString(pdfString(initials))
				kbuf.WriteString("\n")
				kbuf.WriteString(">>\n")

				if err := context.updateObject(uint32(kptr.GetID()), kbuf.Bytes()); err != nil {
					return fmt.Errorf("failed to update kid object %d: %w", kptr.GetID(), err)
				}
			}
		}
	}

	return nil
}
