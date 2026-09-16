package pdfsign

import "testing"

func TestResources_EdgeCases(t *testing.T) {
	doc := &Document{
		fonts:  make(map[string]*Font),
		images: make(map[string]*Image),
	}

	// UseFont checks
	f := doc.UseFont("Unknown", nil)
	if f.Name != "Unknown" {
		t.Error("Should create new font if unknown")
	}
}

func TestFonts_Accessor(t *testing.T) {
	doc := &Document{
		fonts: make(map[string]*Font),
	}
	fonts := doc.Fonts()
	if len(fonts) != 0 {
		t.Error("Fonts() should return empty slice for document with no fonts")
	}

	// Add a font and verify it's returned
	doc.AddFont("TestFont", nil)
	fonts = doc.Fonts()
	if len(fonts) != 1 {
		t.Errorf("Fonts() should return 1 font, got %d", len(fonts))
	}
}

func TestImages_Accessor(t *testing.T) {
	doc := &Document{
		images: make(map[string]*Image),
	}
	images := doc.Images()
	if len(images) != 0 {
		t.Error("Images() should return empty slice for document with no images")
	}

	// Add an image and verify it's returned
	doc.AddImage("TestImage", []byte("fake-image-data"))
	images = doc.Images()
	if len(images) != 1 {
		t.Errorf("Images() should return 1 image, got %d", len(images))
	}
}
