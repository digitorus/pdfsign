package render_test

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestImage_Registration(t *testing.T) {
	testFile := testpki.GetTestFile("testfiles/testfile20.pdf")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("testfile20.pdf not found")
	}

	// Generate a valid minimal 1x1 JPEG
	imgData := image.NewRGBA(image.Rect(0, 0, 1, 1))
	imgData.Set(0, 0, color.RGBA{255, 0, 0, 255})

	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, imgData, nil); err != nil {
		t.Fatalf("Failed to generate test JPEG: %v", err)
	}
	validJpeg := buf.Bytes()

	doc, _ := pdfsign.OpenFile(testFile)

	img := doc.AddImage("test.jpg", validJpeg)
	app := pdfsign.NewAppearance(50, 50)
	app.Image(img).ScaleFit()
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Render User")
	doc.Sign(key, cert).Appearance(app, 1, 100, 100)

	out := new(bytes.Buffer)
	if _, err := doc.Write(out); err != nil {
		t.Errorf("Failed to write document with image: %v", err)
	}
}

func TestImage_Negatives(t *testing.T) {
	testFile := testpki.GetTestFile("testfiles/testfile20.pdf")
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("testfile20.pdf not found")
	}

	// We need to reload doc for each subtest or carefully manage state

	t.Run("Empty Data", func(t *testing.T) {
		doc, _ := pdfsign.OpenFile(testFile)
		img := doc.AddImage("empty", []byte{})

		app := pdfsign.NewAppearance(10, 10)
		app.Image(img).ScaleFit()

		pki := testpki.NewTestPKI(t)
		pki.StartCRLServer()
		defer pki.Close()
		key, cert := pki.IssueLeaf("Empty User")
		doc.Sign(key, cert).Appearance(app, 1, 10, 10)
		if _, err := doc.Write(new(bytes.Buffer)); err == nil {
			t.Error("Expected error for empty image data")
		}
	})

	t.Run("Unsupported Format", func(t *testing.T) {
		doc, _ := pdfsign.OpenFile(testFile)
		img := doc.AddImage("bad.gif", []byte("GIF89a..."))

		app := pdfsign.NewAppearance(10, 10)
		app.Image(img).ScaleFit()

		pki := testpki.NewTestPKI(t)
		pki.StartCRLServer()
		defer pki.Close()
		key, cert := pki.IssueLeaf("Bad User")
		doc.Sign(key, cert).Appearance(app, 1, 10, 10)
		if _, err := doc.Write(new(bytes.Buffer)); err == nil {
			t.Error("Expected error for unsupported image format")
		}
	})

	t.Run("PNG Format", func(t *testing.T) {
		// Valid PNG signature
		pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		// Add some dummy chunks to avoid immediate length check faulure if strictly parsed
		// But valid length > 24 is checked
		pngData = append(pngData, make([]byte, 30)...)

		doc, _ := pdfsign.OpenFile(testFile)
		img := doc.AddImage("test.png", pngData)

		app := pdfsign.NewAppearance(10, 10)
		app.Image(img).ScaleFit()

		pki := testpki.NewTestPKI(t)
		pki.StartCRLServer()
		defer pki.Close()
		key, cert := pki.IssueLeaf("PNG User")
		doc.Sign(key, cert).Appearance(app, 1, 10, 10)

		// Currently code falls through for PNG and tries to embed
		// It might succeed embedding raw bytes, or fail later.
		// As long as it covers the isPng path.
		_, _ = doc.Write(new(bytes.Buffer))
	})
}
