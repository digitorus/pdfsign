package pdfsign

import "testing"

func TestAppearance_FullCoverage(t *testing.T) {
	app := NewAppearance(100, 50)

	// Test chaining and setters
	app.Border(2.0, 0, 0, 0).
		Background(255, 255, 255)

	if app.Width() != 100 || app.Height() != 50 {
		t.Error("Dimensions mismatch")
	}
}
