package pdfsign_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
)

func TestVerify_Execute_NoFile(t *testing.T) {
	// Test behavior when document has no reader (dummy doc)
	doc := &pdfsign.Document{} // initialized without OpenFile

	result := doc.Verify()
	if result.Err() == nil {
		t.Error("Expected error when verifying uninitialized document")
	}
}

// TestVerify_TrustedRoots proves TrustedRoots() actually gates chain trust
// instead of being a no-op: the exact same signed document must verify as
// trusted against its real issuing root, and as untrusted against an
// unrelated root, with TrustSelfSigned left at its secure default (false).
func TestVerify_TrustedRoots(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	key, cert := pki.IssueLeaf("Trusted Roots Tester")

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	doc.Sign(key, cert, pki.Chain()...).Reason("TrustedRoots test")

	var signed bytes.Buffer
	if _, err := doc.Write(&signed); err != nil {
		t.Fatalf("Write: %v", err)
	}

	t.Run("correct root is trusted", func(t *testing.T) {
		verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		result := verifyDoc.Verify().TrustedRoots(pki.RootPool())
		if err := result.Err(); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !result.Valid() {
			t.Fatalf("expected Valid() with the correct root pool, signatures: %+v", result.Signatures())
		}
		if len(result.Signatures()) != 1 || !result.Signatures()[0].TrustedChain {
			t.Errorf("expected TrustedChain=true with the correct root pool, got %+v", result.Signatures())
		}
	})

	t.Run("unrelated root is untrusted", func(t *testing.T) {
		otherPKI := testpki.NewTestPKI(t)
		otherPKI.StartCRLServer()
		defer otherPKI.Close()

		verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		result := verifyDoc.Verify().TrustedRoots(otherPKI.RootPool())
		if result.Valid() {
			t.Fatal("expected Valid()==false against an unrelated root pool")
		}
		if len(result.Signatures()) != 1 || result.Signatures()[0].TrustedChain {
			t.Errorf("expected TrustedChain=false against an unrelated root pool, got %+v", result.Signatures())
		}
	})

	t.Run("no trusted roots and no TrustSelfSigned is untrusted by default", func(t *testing.T) {
		verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		result := verifyDoc.Verify()
		if result.Valid() {
			t.Fatal("expected Valid()==false by default with no TrustedRoots and no TrustSelfSigned")
		}
	})
}

// TestVerify_ConcurrentAccessorCalls proves that once a VerifyBuilder is
// configured, calling its result accessors (Valid, Signatures, Err, Count)
// concurrently from multiple goroutines is safe: verification runs exactly
// once and every goroutine observes the same result. Run with -race to
// exercise the guarantee.
func TestVerify_ConcurrentAccessorCalls(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	key, cert := pki.IssueLeaf("Concurrent Tester")

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	doc.Sign(key, cert, pki.Chain()...).Reason("Concurrency test")

	var signed bytes.Buffer
	if _, err := doc.Write(&signed); err != nil {
		t.Fatalf("Write: %v", err)
	}

	verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	result := verifyDoc.Verify().TrustedRoots(pki.RootPool())

	const goroutines = 50
	var wg sync.WaitGroup
	valids := make([]bool, goroutines)
	counts := make([]int, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			valids[i] = result.Valid()
			counts[i] = result.Count()
			errs[i] = result.Err()
		}(i)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		if valids[i] != valids[0] || counts[i] != counts[0] || errs[i] != errs[0] {
			t.Fatalf("inconsistent result across goroutines: goroutine 0 = (valid=%v, count=%d, err=%v), goroutine %d = (valid=%v, count=%d, err=%v)",
				valids[0], counts[0], errs[0], i, valids[i], counts[i], errs[i])
		}
	}
	if !valids[0] || counts[0] != 1 {
		t.Fatalf("expected a single valid signature, got valid=%v count=%d", valids[0], counts[0])
	}
}

// TestVerify_HTTPTimeoutIsApplied proves VerifyBuilder.HTTPTimeout actually
// bounds external OCSP/CRL requests instead of being a no-op silently
// dropped by doExecute (as it previously was): a signer certificate whose
// OCSP responder never replies must make Valid() return quickly once a
// short HTTPTimeout is configured, rather than wait out the server's full
// (deliberately longer) response delay.
//
// The signer needs a real issuer in its verified chain: applyRevocationStatus
// only attempts an external OCSP check when the chain has more than one
// certificate (chain[0][1], the issuer, is required to build the OCSP
// request) - a self-signed leaf never reaches that code path at all, which
// would make this test pass regardless of whether HTTPTimeout is wired up.
func TestVerify_HTTPTimeoutIsApplied(t *testing.T) {
	slowOCSP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowOCSP.Close()

	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	issuerCert := pki.IntermediateCerts[len(pki.IntermediateCerts)-1]
	issuerKey := pki.IntermediateKeys[len(pki.IntermediateKeys)-1]

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "Slow OCSP Test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}},
		OCSPServer:         []string{slowOCSP.URL},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatal(err)
	}
	// Disable sign-time revocation embedding: by default, signing also
	// fetches OCSP/CRL data to embed for LTV, which would otherwise hit the
	// same slow OCSP server here and confuse what this test measures.
	doc.Sign(key, cert, pki.Chain()...).
		Reason("HTTPTimeout test").
		RevocationFunction(func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
			return nil
		})
	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		t.Fatal(err)
	}

	signedDoc, err := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	signedDoc.Verify().TrustedRoots(pki.RootPool()).ExternalChecks(true).HTTPTimeout(200 * time.Millisecond).Valid()
	elapsed := time.Since(start)

	if elapsed >= time.Second {
		t.Errorf("expected HTTPTimeout(200ms) to abort the slow OCSP request well before the server's 2s response, took %v", elapsed)
	}
}

// TestVerify_ContextCancellation proves VerifyBuilder.Context actually
// bounds external OCSP/CRL requests: cancelling the supplied context must
// make Valid() return quickly even though HTTPTimeout is left at its much
// longer default, and even though the OCSP responder never replies.
func TestVerify_ContextCancellation(t *testing.T) {
	slowOCSP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowOCSP.Close()

	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	issuerCert := pki.IntermediateCerts[len(pki.IntermediateCerts)-1]
	issuerKey := pki.IntermediateKeys[len(pki.IntermediateKeys)-1]

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "Context Cancellation Test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 36}},
		OCSPServer:         []string{slowOCSP.URL},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatal(err)
	}
	doc.Sign(key, cert, pki.Chain()...).
		Reason("Context cancellation test").
		RevocationFunction(func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
			return nil
		})
	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		t.Fatal(err)
	}

	signedDoc, err := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	signedDoc.Verify().TrustedRoots(pki.RootPool()).ExternalChecks(true).Context(ctx).Valid()
	elapsed := time.Since(start)

	if elapsed >= time.Second {
		t.Errorf("expected Context cancellation at 200ms to abort the slow OCSP request well before the server's 2s response, took %v", elapsed)
	}
}

// TestSign_ContextCancellation proves SignBuilder.Context actually bounds
// the TSA HTTP request: cancelling the supplied context must make Write()
// return quickly (with an error) even though the TSA responder never
// replies, rather than hang until it does.
func TestSign_ContextCancellation(t *testing.T) {
	slowTSA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowTSA.Close()

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	doc.Timestamp(slowTSA.URL).Context(ctx)

	var buf bytes.Buffer
	start := time.Now()
	_, err = doc.Write(&buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Write to fail when the TSA request is cancelled by Context")
	}
	if elapsed >= time.Second {
		t.Errorf("expected Context cancellation at 200ms to abort the slow TSA request well before the server's 2s response, took %v", elapsed)
	}
}

// TestVerify_TimestampInfoIsPopulated proves that an embedded RFC 3161
// timestamp's details (time, authority, certificate) surface through
// SignatureVerifyResult.Timestamp. Previously doExecute's Signer-to-
// SignatureVerifyResult mapping never copied verify.Signer.TimeStamp over,
// so this field was always nil even for signatures with a valid embedded
// timestamp.
func TestVerify_TimestampInfoIsPopulated(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	tsaURL := testpki.StartMockTSA(t)
	key, cert := pki.IssueLeaf("Timestamp Info Tester")

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	doc.Sign(key, cert, pki.Chain()...).Reason("Timestamp info test").Timestamp(tsaURL)

	var signed bytes.Buffer
	if _, err := doc.Write(&signed); err != nil {
		t.Fatalf("Write: %v", err)
	}

	verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	result := verifyDoc.Verify().TrustedRoots(pki.RootPool())
	if err := result.Err(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	sigs := result.Signatures()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}

	ts := sigs[0].Timestamp
	if ts == nil {
		t.Fatal("expected Timestamp to be populated for a signature with an embedded RFC 3161 timestamp")
	}
	if ts.Time.IsZero() {
		t.Error("expected Timestamp.Time to be set")
	}
	if ts.Certificate == nil {
		t.Error("expected Timestamp.Certificate to be set")
	}
	if ts.Authority != "Mock TSA" {
		t.Errorf("expected Timestamp.Authority = %q, got %q", "Mock TSA", ts.Authority)
	}
}

// Integration verification tests for specific options are covered in pdf_test.go
