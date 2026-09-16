package verify

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestWarningsJSONShape proves that Signer.Warnings ([]error) still
// marshals to a plain JSON array of strings, matching the shape it had
// when it was []string - existing JSON consumers (e.g. the CLI's --json
// output) see no change despite the underlying type switching to error for
// errors.As support.
func TestWarningsJSONShape(t *testing.T) {
	signer := NewSigner()
	signer.Warnings = append(signer.Warnings, &Warning{Msg: "plain warning"})
	signer.Warnings = append(signer.Warnings, &ContentTypeWarning{
		URL: "http://x", Got: "text/html", Expected: "application/pkix-crl", RFC: "RFC 2585",
	})

	b, err := json.Marshal(signer.Warnings)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("expected warnings to marshal as a plain string array, got %s: %v", b, err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(got))
	}
	if got[0] != "plain warning" {
		t.Errorf("got[0] = %q", got[0])
	}
}

// TestWarningsErrorsAs proves a caller can pick a specific warning kind out
// of Signer.Warnings with errors.As, rather than string-matching messages.
func TestWarningsErrorsAs(t *testing.T) {
	signer := NewSigner()
	signer.Warnings = append(signer.Warnings, &Warning{Msg: "unrelated"})
	signer.Warnings = append(signer.Warnings, &ContentTypeWarning{
		URL: "http://crl.example/crl", Got: "text/html", Expected: "application/pkix-crl", RFC: "RFC 2585 SS4.2",
	})

	joined := errors.Join(signer.Warnings...)

	var ctWarning *ContentTypeWarning
	if !errors.As(joined, &ctWarning) {
		t.Fatal("expected errors.As to find a *ContentTypeWarning in the joined warnings")
	}
	if ctWarning.Got != "text/html" {
		t.Errorf("Got = %q, want %q", ctWarning.Got, "text/html")
	}
}
