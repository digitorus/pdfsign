package extract_test

import (
	"io"
	"os"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// BenchmarkExtractIterator measures the cost of just finding the signature
// objects without extracting heavy data.
func BenchmarkExtractIterator(b *testing.B) {
	// Setup: create a signed file once
	testFile := createSignedBenchmarkFile(b)
	defer func() {
		_ = os.Remove(testFile)
	}()

	fileData, err := os.ReadFile(testFile)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := testpki.NewBytesReader(fileData)
		doc, _ := pdfsign.Open(r, int64(len(fileData)))

		count := 0
		for sig, err := range doc.Signatures() {
			if err != nil {
				b.Fatal(err)
			}
			_ = sig // Just finding it
			count++
		}
		if count == 0 {
			b.Fatal("no signatures found")
		}
	}
}

// BenchmarkExtractContents measures the cost of extracting just the contents (signature blob).
func BenchmarkExtractContents(b *testing.B) {
	testFile := createSignedBenchmarkFile(b)
	defer func() {
		_ = os.Remove(testFile)
	}()
	fileData, _ := os.ReadFile(testFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := testpki.NewBytesReader(fileData)
		doc, _ := pdfsign.Open(r, int64(len(fileData)))

		for sig, _ := range doc.Signatures() {
			_ = sig.Contents()
		}
	}
}

// BenchmarkExtractSignedData measures the cost of getting the reader for signed data.
// It DOES NOT consume the reader to verify strict overhead of the API call itself,
// effectively benchmarking the setup cost.
func BenchmarkExtractSignedData_Setup(b *testing.B) {
	testFile := createSignedBenchmarkFile(b)
	defer func() {
		_ = os.Remove(testFile)
	}()
	fileData, _ := os.ReadFile(testFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := testpki.NewBytesReader(fileData)
		doc, _ := pdfsign.Open(r, int64(len(fileData)))

		for sig, _ := range doc.Signatures() {
			_, _ = sig.SignedData()
		}
	}
}

// BenchmarkExtractSignedData_ReadAll reads the full data to compare with previous baseline.
func BenchmarkExtractSignedData_ReadAll(b *testing.B) {
	testFile := createSignedBenchmarkFile(b)
	defer func() {
		_ = os.Remove(testFile)
	}()
	fileData, _ := os.ReadFile(testFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := testpki.NewBytesReader(fileData)
		doc, _ := pdfsign.Open(r, int64(len(fileData)))

		for sig, _ := range doc.Signatures() {
			reader, _ := sig.SignedData()
			_, _ = io.ReadAll(reader)
		}
	}
}

// Helper to create a signed file for benchmarking
func createSignedBenchmarkFile(b *testing.B) string {
	// Create a simple PDF
	tmpFile, err := os.CreateTemp("", "bench_sig_*.pdf")
	if err != nil {
		b.Fatal(err)
	}
	_ = tmpFile.Close()

	// Create a dummy PDF content if needed
	src := "testfiles/testfile20.pdf"
	data, err := os.ReadFile(src)
	if err != nil {
		b.Skipf("Benchmark requires %s", src)
	}
	_ = os.WriteFile(tmpFile.Name(), data, 0644)

	// Sign it
	cert, key := testpki.LoadBenchKeys() // now in internal/testpki
	doc, err := pdfsign.OpenFile(tmpFile.Name())
	if err != nil {
		b.Fatal(err)
	}

	doc.Sign(key, cert).Reason("Benchmark")

	// Write signed result
	out, err := os.CreateTemp("", "bench_signed_*.pdf")
	if err != nil {
		b.Fatal(err)
	}
	_, _ = doc.Write(out)
	_ = out.Close()
	_ = os.Remove(tmpFile.Name()) // Clean up input

	return out.Name()
}
