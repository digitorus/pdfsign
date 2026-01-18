package verify

import "fmt"

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
