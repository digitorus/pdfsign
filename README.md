# Signing PDF files with Go

[![Build & Test](https://github.com/digitorus/pdfsign/workflows/Build%20&%20Test/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Abuild-and-test)
[![golangci-lint](https://github.com/digitorus/pdfsign/workflows/golangci-lint/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Agolangci-lint)
[![Go Report Card](https://goreportcard.com/badge/github.com/digitorus/pdfsign)](https://goreportcard.com/report/github.com/digitorus/pdfsign)
[![Coverage Status](https://codecov.io/gh/digitorus/pdfsign/branch/main/graph/badge.svg)](https://codecov.io/gh/)
[![Go Reference](https://pkg.go.dev/badge/github.com/digitorus/pdfsign.svg)](https://pkg.go.dev/github.com/digitorus/pdfsign)

A PDF signing and verification library written in [Go](https://go.dev). This library provides both command-line tools and Go APIs for digitally signing and verifying PDF documents.

**See also our [PDFSigner](https://github.com/digitorus/pdfsigner/), a more advanced digital signature server that is using this project.**

## Quick Start

```bash
# Sign a PDF
./pdfsign sign -name "John Doe" input.pdf output.pdf certificate.crt private_key.key

# Verify a PDF signature
./pdfsign verify document.pdf
```

## Package Architecture

The library is organized into specialized subpackages, though most users will primarily interact with the root `pdfsign` package.

| Package | Purpose |
|:--- |:--- |
| **`pdfsign`** | **Primary entry point**. Provides the fluent API for signing, verification, and document management. |
| **`extract`** | Low-level signature inspection. Allows extracting raw PKCS#7 envelopes and signed data. |
| **`forms`** | PDF form handling. Logic for field discovery and generating PDF object updates. |
| **`initials`** | Configuration and placement logic for signing initials across multiple pages. |
| **`signers/...`** | **External Signers**. Optional integrations for remote signing (CSC, KMS, PKCS#11). |
| **`fonts`** | Font resource management and TrueType (TTF) metric parsing for accurate positioning. |
| **`images`** | Image resource handling for visual signatures. |
| **`internal/...`** | Private implementation details for PDF scanning and rendering. |

## PDF Signing

### Command Line Usage

```bash
./pdfsign sign [options] <input.pdf> <output.pdf> <certificate.crt> <private_key.key> [chain.crt]
```

### Signing Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-name` | string | | Name of the signatory |
| `-location` | string | | Location of the signatory |
| `-reason` | string | | Reason for signing |
| `-contact` | string | | Contact information for signatory |
| `-certType` | string | `CertificationSignature` | Certificate type: `CertificationSignature`, `ApprovalSignature`, `UsageRightsSignature`, `TimeStampSignature` |
| `-tsa` | string | `https://freetsa.org/tsr` | URL for Time-Stamp Authority |

### Signing Examples

```bash
# Basic signing
./pdfsign sign -name "John Doe" input.pdf output.pdf cert.crt key.key

# Signing with additional metadata
./pdfsign sign -name "John Doe" -location "New York" -reason "Document approval" input.pdf output.pdf cert.crt key.key

# Timestamp-only signature
./pdfsign sign -certType "TimeStampSignature" input.pdf output.pdf
```

## PDF Verification

### Command Line Usage

```bash
./pdfsign verify [options] <input.pdf>
```

### Verification Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `-external` | bool | `false` | Enable external OCSP and CRL checking |
| `-require-digital-signature` | bool | `true` | Require Digital Signature key usage in certificates |
| `-require-non-repudiation` | bool | `false` | Require Non-Repudiation key usage in certificates (for highest security) |
| `-trust-signature-time` | bool | `false` | Trust the signature time embedded in the PDF if no timestamp is present (untrusted by default) |
| `-validate-timestamp-certs` | bool | `true` | Validate timestamp token certificates |
| `-allow-untrusted-roots` | bool | `false` | Allow certificates embedded in the PDF to be used as trusted roots (use with caution) |
| `-http-timeout` | duration | `10s` | Timeout for external revocation checking requests |

### Verification Examples

```bash
# Basic verification (always uses embedded timestamps when present)
./pdfsign verify document.pdf

# Verification with external revocation checking
./pdfsign verify -external -http-timeout=30s document.pdf

# Verification trusting signature time as fallback
./pdfsign verify -trust-signature-time document.pdf

# Highest security verification (requires Non-Repudiation key usage)
./pdfsign verify -require-non-repudiation -external document.pdf

# Verification allowing self-signed certificates
./pdfsign verify -allow-untrusted-roots self-signed.pdf
```

### Verification Output

The verification command outputs JSON with the following key fields:

| Field | Description |
|-------|-------------|
| `ValidSignature` | Whether the cryptographic signature is mathematically valid |
| `TrustedIssuer` | Whether the certificate chain is trusted by system root certificates |
| `RevokedCertificate` | Whether any certificate in the chain has been revoked before signing |
| `KeyUsageValid` | Whether the certificate has appropriate key usage for PDF signing |
| `ExtKeyUsageValid` | Whether the certificate has proper Extended Key Usage (EKU) values |
| `TimestampStatus` | Status of embedded timestamp: "valid", "invalid", or "missing" |
| `TimestampTrusted` | Whether the timestamp token's certificate chain is trusted |
| `VerificationTime` | The time used for certificate validation |
| `TimeSource` | Source of verification time: "embedded_timestamp", "signature_time", or "current_time" |
| `TimeWarnings` | Warnings about time validation (e.g., using untrusted signature time) |
| `OCSPEmbedded` | Whether OCSP response is embedded in the PDF |
| `OCSPExternal` | Whether external OCSP checking was performed |
| `CRLEmbedded` | Whether CRL is embedded in the PDF |
| `CRLExternal` | Whether external CRL checking was performed |
| `RevocationTime` | When the certificate was revoked (if applicable) |
| `RevokedBeforeSigning` | Whether revocation occurred before the signing time |
| `RevocationWarning` | Human-readable warning about revocation status checking |


### Go Library Usage

The `pdfsign` package provides a modern, fluent API for signing and verification.

### Opening Documents

You can open PDFs from a file path or any `io.ReaderAt`.

```go
// Open from file
doc, err := pdfsign.OpenFile("document.pdf")

// Open from memory (byte slice)
data, _ := os.ReadFile("document.pdf")
reader := bytes.NewReader(data)
doc, err := pdfsign.Open(reader, int64(len(data)))
```

### Basic Signing

```go
package main

import (
    "os"
    "github.com/digitorus/pdfsign"
)

func main() {
    doc, _ := pdfsign.OpenFile("contract.pdf")
    
    // Create visual appearance
    appearance := pdfsign.NewAppearance(250, 80)
    appearance.Text("Signed by: {{Name}}").Position(10, 60)
    
    // Configure and write
    output, _ := os.Create("signed.pdf")
    doc.Sign(certificate, privateKey).
        Reason("Approved").
        Location("New York").
        Appearance(appearance, 1, 400, 50)
        
    _, err := doc.Write(output)
}
```

### Form Filling

You can interact with PDF forms by listing, setting, and unsetting fields.

#### List Form Fields
```go
fields := doc.FormFields()
for _, f := range fields {
    fmt.Printf("Field: %s (Type: %s, Value: %v)\n", f.Name, f.Type, f.Value)
}
```

#### Fill Form Fields
Form changes are applied when `Write()` is called, alongside any signatures.

```go
// Set a text field
if err := doc.SetField("Full Name", "John Doe"); err != nil {
    log.Fatal(err)
}

// Unset/Clear a field
if err := doc.SetField("Comments", ""); err != nil {
    log.Fatal(err)
}

// Write the changes (with or without a signature)
// If you only want to fill forms without signing:
// doc.Write(output)

// If you want to sign AND fill:
doc.Sign(signer, cert).Reason("Form Filled").Write(output)
```

### Signature Extraction

You can iterate over all signatures in a document to inspect their properties or extract raw data without performing full cryptographic verification.

```go
// Iterate through signatures
for sig, err := range doc.Signatures() {
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Signer: %s\n", sig.Name())
    fmt.Printf("Filter: %s\n", sig.Filter())
    fmt.Printf("SubFilter: %s\n", sig.SubFilter())

    // Access raw PKCS#7 signature envelope
    envelope := sig.Contents()
    fmt.Printf("Signature size: %d bytes\n", len(envelope))

    // Read the actual bytes of the document covered by the signature
    reader, _ := sig.SignedData()
    data, _ := io.ReadAll(reader)
    fmt.Printf("Signed data size: %d bytes\n", len(data))
}
```

### Initials

```go
// Add initials to all pages (except page 1)
initials := pdfsign.NewAppearance(60, 40)

// Optional: Use custom font
// font := doc.AddFont("Handwriting", fontBytes)
// initials.Text("JD").Font(font, 24).Center()

initials.Text("{{Initials}}").Font(nil, 12).Center()

doc.AddInitials(initials).
    Position(pdfsign.BottomRight, 30, 30).
    ExcludePages(1)
```

## Verification

The verification API uses a fluent builder pattern with lazy execution. Verification is triggered when you access result properties.

```go
doc, _ := pdfsign.OpenFile("signed.pdf")

// Configure verification with chainable methods
result := doc.Verify().
    TrustSelfSigned(false).   // Security: Reject self-signed/untrusted CAs
    ExternalChecks(true).     // Enable online revocation checks
    MinRSAKeySize(2048)       // Enforce minimum key size

// Accessing .Valid() triggers the actual verification
if result.Valid() {
    fmt.Println("Document is valid!")
    for _, sig := range result.Signatures() {
        fmt.Printf("Signed by %s at %s\n", sig.SignerName, sig.SigningTime)
    }
}

// Check for errors
if result.Err() != nil {
    fmt.Printf("Verification error: %v\n", result.Err())
}
```

### Strict Verification

Use `Strict()` to enable all security checks at once:

```go
result := doc.Verify().Strict()  // Enables all security constraints

if result.Valid() {
    fmt.Printf("Document passed strict verification (%d signatures)\n", result.Count())
}
```

### Compression

Optimize file size by configuring compression levels (powered by `compress/zlib`).

```go
import "compress/zlib"

// ...
doc, _ := pdfsign.OpenFile("large.pdf")

// Options: zlib.DefaultCompression, zlib.BestCompression, zlib.BestSpeed, zlib.NoCompression
doc.SetCompression(zlib.BestCompression)
```

### Custom Fonts

Embed TrueType fonts for realistic signatures and styling. Font metrics are automatically parsed for accurate text positioning.

```go
fontData, _ := os.ReadFile("MySignatureFont.ttf")
customFont := doc.AddFont("MySig", fontData)

appearance := pdfsign.NewAppearance(200, 80)
appearance.Text("John Doe").Font(customFont, 24).Center()
```

> **Note:** When you call `AddFont()` with TTF data, the library automatically parses glyph widths for accurate text measurement and centering.

### Standard Appearance

Use the built-in standard appearance for a professional signature with metadata:

```go
// Standard appearance with Name, Reason, Location, and Date
appearance := pdfsign.NewAppearance(300, 100).Standard()

doc.Sign(signer, cert).
    SignerName("John Doe").
    Reason("Contract Agreement").
    Location("Amsterdam, NL").
    Appearance(appearance, 1, 100, 100)
```

The `Standard()` method automatically adds:
- Signer name (larger font)
- Reason
- Location  
- Date

Template variables (`{{Name}}`, `{{Reason}}`, `{{Location}}`, `{{Date}}`) are expanded at render time.

### Crypto Settings

Configure hash algorithms and use custom signers (HSM, Tokens, Cloud):

```go
import "crypto"

// Custom hash algorithm (default: SHA256)
doc.Sign(signer, cert).
    Digest(crypto.SHA384)  // or crypto.SHA512

// HSM/Token signing - any crypto.Signer works
hsmSigner := pkcs11.NewSigner(slot, pin)  // Your HSM implementation
doc.Sign(hsmSigner, cert).
    Digest(crypto.SHA256)
```

The signature algorithm is determined by your `crypto.Signer` implementation (RSA, ECDSA, Ed25519).

### External Signers (Integrations)

The `signers/` directory contains "best-effort" implementations and skeletons for various external signing systems. These are provided as examples to help you integrate with hardware security modules and cloud services.

#### Cloud Signing (CSC API)

Sign documents using a remote Cloud Signature Consortium (CSC) compliant service:

```go
import "github.com/digitorus/pdfsign/signers/csc"

// Connect to your CSC-compliant signing service
signer, _ := csc.NewSigner(csc.Config{
    BaseURL:      "https://signing-service.example.com/csc/v1",
    CredentialID: "my-signing-key",
    AuthToken:    "Bearer ey...",
    PIN:          "123456",  // Optional
})

doc.Sign(signer, cert).Reason("Cloud Signed")
```

#### Cloud KMS and PKCS#11

We provide functional implementations for major cloud providers and HSMs. Each integration is a standalone module to minimize core dependencies.

```go
import (
    "github.com/digitorus/pdfsign/signers/aws"
    "github.com/digitorus/pdfsign/signers/gcp"
    "github.com/digitorus/pdfsign/signers/azure"
    "github.com/digitorus/pdfsign/signers/pkcs11"
)

// Example: AWS KMS Signer
// client is a *kms.Client from aws-sdk-go-v2
awsSigner, _ := aws.NewSigner(client, "key-id-or-arn", publicKey)
doc.Sign(awsSigner, cert)

// Example: Google Cloud KMS Signer
// client is a *kms.KeyManagementClient
gcpSigner, _ := gcp.NewSigner(client, "key-resource-name", publicKey)
doc.Sign(gcpSigner, cert)

// Example: Azure Key Vault Signer
// client is a *azkeys.Client
azureSigner, _ := azure.NewSigner(client, "key-name", "key-version", publicKey)
doc.Sign(azureSigner, cert)

// Example: PKCS#11 / HSM Signer
hsmSigner, _ := pkcs11.NewSigner("/usr/lib/libpkcs11.so", "token-label", "key-label", "pin", publicKey)
doc.Sign(hsmSigner, cert)
```

> [!TIP]
> Each integration is designed to be a standalone module. This prevents your core application from dragging in heavy cloud SDKs unless you specifically import and use them.

## Development

### DSS Validation

For automated validation of signed PDFs against European standards, we use the [Digital Signature Service (DSS)](https://github.com/esig/dss).

#### Local Setup

A local DSS instance is required for running the signature validation tests. You can set it up using the provided script, which supports both Docker and Apple's native `container` CLI:

> [!NOTE]
> On Apple Silicon (M1/M2/M3), the `container` tool requires **Rosetta 2**. If you haven't installed it yet, you can do so with:
> `softwareupdate --install-rosetta --agree-to-license`

```bash
# Build and start the DSS service
./scripts/setup-dss.sh
```

The script will:
1. Detect if `container` (Apple Silicon native) or `docker` is available.
2. Build the `dss-validator` image from source.
3. Start the service on `http://localhost:8080`.

#### Running Validation Tests

Once the DSS service is running, you can run the validation tests:

```bash
export DSS_API_URL=http://localhost:8080/services/rest/validation/v2/validateSignature
go test -v ./sign -run TestSignDSSValidation
```

## Legacy API (Deprecated)

The old `sign.SignFile` and `verify.VerifyFile` APIs are deprecated. Please migrate to the `pdfsign` package.
