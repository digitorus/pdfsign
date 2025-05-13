# Signing PDF files with Go

[![Build & Test](https://github.com/digitorus/pdfsign/workflows/Build%20&%20Test/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Abuild-and-test)
[![golangci-lint](https://github.com/digitorus/pdfsign/workflows/golangci-lint/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Agolangci-lint)
[![Go Report Card](https://goreportcard.com/badge/github.com/digitorus/pdfsign)](https://goreportcard.com/report/github.com/digitorus/pdfsign)
[![Coverage Status](https://codecov.io/gh/digitorus/pdfsign/branch/main/graph/badge.svg)](https://codecov.io/gh/)
[![Go Reference](https://pkg.go.dev/badge/github.com/digitorus/pdfsign.svg)](https://pkg.go.dev/github.com/digitorus/pdfsign)

This PDF signing library is written in [Go](https://go.dev). The library is in development, might not work for all PDF files and the API might change, bug reports, contributions and suggestions are welcome.

**See also our [PDFSigner](https://github.com/digitorus/pdfsigner/), a more advanced digital signature server that is using this project.**

## From the command line

```
Usage of ./pdfsign:
  -certType string
        Type of the certificate (CertificationSignature, ApprovalSignature, UsageRightsSignature, TimeStampSignature) (default "CertificationSignature")
  -contact string
        Contact information for signatory
  -location string
        Location of the signatory
  -name string
        Name of the signatory
  -reason string
        Reason for signing
  -tsa string
        URL for Time-Stamp Authority (default "https://freetsa.org/tsr")

Example usage:
        ./pdfsign -name "Jon Doe" sign input.pdf output.pdf certificate.crt private_key.key [chain.crt]
        ./pdfsign -certType "CertificationSignature" -name "Jon Doe" sign input.pdf output.pdf certificate.crt private_key.key [chain.crt]
        ./pdfsign -certType "TimeStampSignature" input.pdf output.pdf
        ./pdfsign verify input.pdf
```

## As library

```go
import "github.com/digitorus/pdf"

input_file, err := os.Open(input)
if err != nil {
    return err
}
defer input_file.Close()

output_file, err := os.Create(output)
if err != nil {
    return err
}
defer output_file.Close()

finfo, err := input_file.Stat()
if err != nil {
    return err
}
size := finfo.Size()

rdr, err := pdf.NewReader(input_file, size)
if err != nil {
    return err
}

err = sign.Sign(input_file, output_file, rdr, size, sign.SignData{
    Signature: sign.SignDataSignature{
        Info: sign.SignDataSignatureInfo{
            Name:        "John Doe",
            Location:    "Somewhere on the globe",
            Reason:      "My season for siging this document",
            ContactInfo: "How you like",
            Date:        time.Now().Local(),
        },
        CertType:   sign.CertificationSignature,
        DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
    },
    Signer:            privateKey,         // crypto.Signer
    DigestAlgorithm:   crypto.SHA256,      // hash algorithm for the digest creation
    Certificate:       certificate,        // x509.Certificate
    CertificateChains: certificate_chains, // x509.Certificate.Verify()
    TSA: sign.TSA{
        URL: "https://freetsa.org/tsr",
        Username: "",
        Password: "",
    },

    // The follow options are likely to change in a future release
    //
    // cache revocation data when bulk signing
    RevocationData:     revocation.InfoArchival{}, 
    // custom revocation lookup
    RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
})
if err != nil {
    log.Println(err)
} else {
    log.Println("Signed PDF written to " + output)
}

```

## Signature Appearance with Text and / or Images

You can add an image (JPG or PNG) to the visible signature appearance. This is useful for including a handwritten signature or a company logo in the signature field.

**Supported image formats:** JPG and PNG.

### Example: Signing a PDF with a visible signature and image

```go
// Read the signature image file
signatureImage, err := os.ReadFile("signature.jpg")
if err != nil {
    log.Fatal(err)
}

err := sign.Sign(inputFile, outputFile, rdr, size, sign.SignData{
    Signature: sign.SignDataSignature{
        Info: sign.SignDataSignatureInfo{
            Name:        "John Doe",
            Location:    "Somewhere",
            Reason:      "Signed with image",
            ContactInfo: "None",
            Date:        time.Now().Local(),
        },
        CertType:   sign.ApprovalSignature,
        DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
    },
    Appearance: sign.Appearance{
        Visible:     true,
        LowerLeftX:  400,
        LowerLeftY:  50,
        UpperRightX: 600,
        UpperRightY: 125,
        Image:       signatureImage, // JPG or PNG image bytes
        // ImageAsWatermark: true,   // Optional: set to true to draw text over the image
    },
    DigestAlgorithm: crypto.SHA512,
    Signer:          privateKey,
    Certificate:     certificate,
})
if err != nil {
    log.Fatal(err)
}
```

### Key Features:

1. **Image Support**: Both JPG and PNG formats are supported
2. **Flexible Positioning**: Control signature placement with LowerLeftX/Y and UpperRightX/Y coordinates
3. **Watermark Mode**: Optional ImageAsWatermark setting allows drawing text over the image
4. **Transparency Support**: PNG images with alpha channel (transparency) are properly handled

### Notes:
- The image will be scaled to fit the signature rectangle while maintaining its aspect ratio
- For optimal results, prepare your image with the desired dimensions and transparency before using it
- Only visible approval signatures can include images
