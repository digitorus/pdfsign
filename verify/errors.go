package verify

import (
	"encoding/json"
	"fmt"
)

// ValidationError represents a general validation error in the verification process.
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string {
	return e.Msg
}

// RevocationError represents an error during revocation checking (CRL/OCSP).
type RevocationError struct {
	Msg string
	Err error
}

func (e *RevocationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	}
	return e.Msg
}

func (e *RevocationError) Unwrap() error {
	return e.Err
}

// InvalidSignatureError indicates that the cryptographic signature verification failed.
type InvalidSignatureError struct {
	Msg string
}

func (e *InvalidSignatureError) Error() string {
	return e.Msg
}

// PolicyError indicates a violation of validation policy (e.g. key size).
type PolicyError struct {
	Msg string
}

func (e *PolicyError) Error() string {
	return e.Msg
}

// Warning represents a general non-fatal condition surfaced during
// verification: the operation it's attached to still succeeded overall, but
// there's something worth telling the caller about. Use a more specific
// warning type (e.g. ContentTypeWarning) instead when there's structured
// data worth preserving for callers to match on with errors.As.
type Warning struct {
	Msg string
}

func (w *Warning) Error() string {
	return w.Msg
}

func (w *Warning) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.Msg)
}

// ContentTypeWarning indicates an external OCSP/CRL response's declared
// Content-Type didn't match the value the relevant RFC specifies. It's
// non-fatal - the response body is still read and processed - but callers
// enforcing strict RFC compliance on responders can detect it with
// errors.As instead of string-matching a message.
type ContentTypeWarning struct {
	URL      string
	Got      string
	Expected string
	RFC      string
}

func (w *ContentTypeWarning) Error() string {
	return fmt.Sprintf("response from %s had Content-Type %q, expected %q per %s", w.URL, w.Got, w.Expected, w.RFC)
}

func (w *ContentTypeWarning) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.Error())
}
