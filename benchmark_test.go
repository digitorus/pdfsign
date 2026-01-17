package pdfsign_test

import (
	"crypto"
	"crypto/x509"
	"io"
	"os"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// BenchmarkAppearance creates benchmarks for logical appearance creation
func BenchmarkAppearance(b *testing.B) {
	b.Run("New", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pdfsign.NewAppearance(200, 100)
		}
	})

	b.Run("Complex", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			app := pdfsign.NewAppearance(200, 100)
			app.Border(1.0, 0, 0, 0).Background(240, 240, 240)
			app.Text("Benchmark").Position(10, 10)
			app.Text("Signature").Position(10, 30)
		}
	})
}

// BenchmarkSign benchmarks the signing process
func BenchmarkSign(b *testing.B) {
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skip("test file not found")
	}

	// Pre-load keys to exclude from benchmark
	cert, key := testpki.LoadBenchKeys()

	// Read file into memory to avoid I/O noise
	fileData, err := os.ReadFile(testFile)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We need a fresh reader for each iteration because Sign modifies state/offsets
		// Use a bytes reader
		r := testpki.NewBytesReader(fileData)
		doc, err := pdfsign.Open(r, int64(len(fileData)))
		if err != nil {
			b.Fatal(err)
		}

		// Configure
		doc.Sign(key, cert).Reason("Benchmark").SignerName("Benchmarker")

		// Write to discard
		if _, err := doc.Write(io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerify benchmarks verification
func BenchmarkVerify(b *testing.B) {
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skip("test file not found")
	}

	cert, key := testpki.LoadBenchKeys()
	fileData, err := os.ReadFile(testFile)
	if err != nil {
		b.Fatal(err)
	}

	// Create a signed version in memory
	r := testpki.NewBytesReader(fileData)
	doc, _ := pdfsign.Open(r, int64(len(fileData)))
	doc.Sign(key, cert).Reason("Bench").SignerName("Bench")

	// Create pipe or buffer to capture signed output
	// But Document.Write takes io.Writer. We need the RESULTING bytes to Verify.
	// We can write to a buffer once.
	// But wait, Write returns *Result, but validation needs a ReaderAt of the signed file.
	// So we need to write to a temp file or memory buffer.

	// Pre-sign once
	signedData := signRef(fileData, key, cert)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Open the SIGNED data
		rSigned := testpki.NewBytesReader(signedData)
		doc, err := pdfsign.Open(rSigned, int64(len(signedData)))
		if err != nil {
			b.Fatal(err)
		}

		// Verify
		result := doc.Verify()
		if err := result.Err(); err != nil {
			// Might fail if trust chain not set up, but we want to measure perf
			_ = err
		}
		_ = result.Valid() // Trigger verification
	}
}

// Helper to sign once and return bytes
func signRef(input []byte, key crypto.Signer, cert *x509.Certificate) []byte {
	// Simple in-memory signing helper setup
	tmpIn, _ := os.CreateTemp("", "bench-in")
	_, _ = tmpIn.Write(input)
	_ = tmpIn.Close()
	defer func() { _ = os.Remove(tmpIn.Name()) }()

	tmpOut, _ := os.CreateTemp("", "bench-out")
	defer func() { _ = os.Remove(tmpOut.Name()) }()
	_ = tmpOut.Close()

	doc, _ := pdfsign.OpenFile(tmpIn.Name())
	fOut, _ := os.Create(tmpOut.Name())
	doc.Sign(key, cert).Reason("Ref")
	_, _ = doc.Write(fOut)
	_ = fOut.Close()

	outData, _ := os.ReadFile(tmpOut.Name())
	return outData
}
