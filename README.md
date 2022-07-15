# Signing PDF files with Go

[![Build & Test](https://github.com/digitorus/pdfsign/workflows/Build%20&%20Test/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Abuild-and-test)
[![golangci-lint](https://github.com/digitorus/pdfsign/workflows/golangci-lint/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Agolangci-lint)
[![CodeQL](https://github.com/digitorus/pdfsign/workflows/CodeQL/badge.svg)](https://github.com/digitorus/pdfsign/actions?query=workflow%3Acodeql)
[![Go Report Card](https://goreportcard.com/badge/github.com/digitorus/pdfsign)](https://goreportcard.com/report/github.com/digitorus/pdfsign)
[![Coverage Status](https://codecov.io/gh/digitorus/pdfsign/branch/master/graph/badge.svg)](https://codecov.io/gh/digitorus/pdfsign)
[![Go Reference](https://pkg.go.dev/badge/github.com/digitorus/pdfsign.svg)](https://pkg.go.dev/github.com/digitorus/pdfsign)

This PDF signing library is written in [Go](https://go.dev). The library is in development, might not work for all PDF files and the API might change, bug reports, contributions and suggestions are welcome.

**See also our [PDFSigner](https://github.com/digitorus/pdfsigner/), a more advanced digital signature server that is using this project.**

## From the command line

```
Usage of ./pdfsign:
  -contact string
        Contact information for signatory
  -location string
        Location of the signatory
  -name string
        Name of the signatory
  -reason string
        Reason for signig
  -tsa string
        URL for Time-Stamp Authority (default "https://freetsa.org/tsr")

Example usage:
        ./pdfsign -name "Jon Doe" sign input.pdf output.pdf certificate.crt private_key.key [chain.crt]
        ./pdfsignverify input.pdf
```

## As library

```go
import "bitbucket.org/digitorus/pdf"

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
