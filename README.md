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

# Get help for specific commands
./pdfsign sign -h
./pdfsign verify -h
```

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

## Go Library Usage

### Basic Signing

```go
package main

import (
    "crypto"
    "os"
    "time"
    
    "github.com/digitorus/pdf"
    "github.com/digitorus/pdfsign/sign"
)

func main() {
    inputFile, err := os.Open("input.pdf")
    if err != nil {
        panic(err)
    }
    defer inputFile.Close()

    outputFile, err := os.Create("output.pdf")
    if err != nil {
        panic(err)
    }
    defer outputFile.Close()

    // Load certificate and private key
    certificate := loadCertificate("cert.crt")
    privateKey := loadPrivateKey("key.key")

    err = sign.SignFile("input.pdf", "output.pdf", sign.SignData{
        Signature: sign.SignDataSignature{
            Info: sign.SignDataSignatureInfo{
                Name:        "John Doe",
                Location:    "New York",
                Reason:      "Document approval",
                ContactInfo: "john@example.com",
                Date:        time.Now().Local(),
            },
            CertType:   sign.CertificationSignature,
            DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
        },
        Signer:          privateKey,
        DigestAlgorithm: crypto.SHA256,
        Certificate:     certificate,
        TSA: sign.TSA{
            URL: "https://freetsa.org/tsr",
        },
    })
    if err != nil {
        panic(err)
    }
}
```

### Basic Verification

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"
    
    "github.com/digitorus/pdfsign/verify"
)

func main() {
    file, err := os.Open("document.pdf")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    response, err := verify.VerifyFile(file)
    if err != nil {
        panic(err)
    }

    jsonData, _ := json.MarshalIndent(response, "", "  ")
    fmt.Println(string(jsonData))
}
```

### Advanced Verification with Timestamp and External Checking

```go
package main

import (
    "net/http"
    "time"
    
    "github.com/digitorus/pdfsign/verify"
)

func main() {
    file, err := os.Open("document.pdf")
    if err != nil {
        panic(err)
    }
    defer file.Close()

    options := verify.DefaultVerifyOptions()
    options.EnableExternalRevocationCheck = true
    options.TrustSignatureTime = true  // Allow fallback to signature time
    options.ValidateTimestampCertificates = true  // Always validate timestamp certs
    options.HTTPTimeout = 15 * time.Second
    
    // Optional: Custom HTTP client for proxy support
    options.HTTPClient = &http.Client{
        Timeout: 20 * time.Second,
    }

    response, err := verify.VerifyFileWithOptions(file, options)
    if err != nil {
        panic(err)
    }
    
    // Check timestamp validation results
    for _, signer := range response.Signers {
        fmt.Printf("Time source: %s\n", signer.TimeSource)
        fmt.Printf("Timestamp status: %s\n", signer.TimestampStatus)
        fmt.Printf("Timestamp trusted: %v\n", signer.TimestampTrusted)
        
        if len(signer.TimeWarnings) > 0 {
            fmt.Println("Time warnings:")
            for _, warning := range signer.TimeWarnings {
                fmt.Printf("  - %s\n", warning)
            }
        }
    }
}
```

### Library Verification Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `EnableExternalRevocationCheck` | bool | `false` | Perform OCSP and CRL checks via network requests |
| `HTTPClient` | `*http.Client` | `nil` | Custom HTTP client for external checks (proxy support) |
| `HTTPTimeout` | `time.Duration` | `10s` | Timeout for external revocation checking requests |
| `RequireDigitalSignatureKU` | bool | `true` | Require Digital Signature key usage in certificates |
| `AllowNonRepudiationKU` | bool | `true` | Allow Non-Repudiation key usage (recommended for PDF signing) |
| `TrustSignatureTime` | bool | `false` | Trust the signature time embedded in the PDF if no timestamp is present (untrusted by default) |
| `ValidateTimestampCertificates` | bool | `true` | Validate timestamp token's certificate chain and revocation status |
| `AllowUntrustedRoots` | bool | `false` | Allow certificates embedded in the PDF to be used as trusted roots (use with caution) |

## Signature Appearance with Images

Add visible signatures with custom images to your PDF documents.

### Supported Features

- **Image formats**: JPG and PNG
- **Transparency**: PNG alpha channel support
- **Positioning**: Precise coordinate control
- **Scaling**: Automatic aspect ratio preservation

### Usage Example

```go
// Read signature image
signatureImage, err := os.ReadFile("signature.jpg")
if err != nil {
    panic(err)
}

err = sign.Sign(inputFile, outputFile, rdr, size, sign.SignData{
    Signature: sign.SignDataSignature{
        Info: sign.SignDataSignatureInfo{
            Name:        "John Doe",
            Location:    "New York",
            Reason:      "Signed with image",
            ContactInfo: "john@example.com",
            Date:        time.Now().Local(),
        },
        CertType: sign.ApprovalSignature,
    },
    Appearance: sign.Appearance{
        Visible:     true,
        LowerLeftX:  400,
        LowerLeftY:  50,
        UpperRightX: 600,
        UpperRightY: 125,
        Image:       signatureImage,
        // ImageAsWatermark: true, // Optional: draw text over image
    },
    DigestAlgorithm: crypto.SHA512,
    Signer:          privateKey,
    Certificate:     certificate,
})
```

## Limitations

### SHA1 Algorithm Support

**Important**: This library does not support SHA1-based cryptographic operations due to Go's security policies. SHA1 has been deprecated and is considered cryptographically insecure.

**Impact on Revocation Checking**:
- OCSP responders and CRL distribution points that use SHA1 signatures will fail verification
- External revocation checking (`-external` flag or `EnableExternalRevocationCheck` option) may fail for certificates signed with SHA1
- Legacy PKI infrastructure still using SHA1 may not be compatible with this library

**Recommendation**: Use certificates and PKI infrastructure that support modern hash algorithms (SHA-256 or higher).

## Development Status

This library is under active development. The API may change and some PDF files might not work correctly. Bug reports, contributions, and suggestions are welcome.

For production use, consider our [PDFSigner](https://github.com/digitorus/pdfsigner/) server solution.
