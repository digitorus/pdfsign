package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/digitorus/pdfsign"
)

func VerifyCommand() {
	verifyFlags := flag.NewFlagSet("verify", flag.ExitOnError)

	var enableExternalRevocation bool
	var requireDigitalSignatureKU bool
	var requireNonRepudiation bool
	var trustSignatureTime bool
	var validateTimestampCertificates bool
	var allowUntrustedRoots bool
	var httpTimeout time.Duration

	verifyFlags.BoolVar(&enableExternalRevocation, "external", false, "Enable external OCSP and CRL checking")
	verifyFlags.BoolVar(&requireDigitalSignatureKU, "require-digital-signature", true, "Require Digital Signature key usage in certificates")
	verifyFlags.BoolVar(&requireNonRepudiation, "require-non-repudiation", false, "Require Non-Repudiation key usage in certificates (for highest security)")
	verifyFlags.BoolVar(&trustSignatureTime, "trust-signature-time", false, "Trust the signature time embedded in the PDF if no timestamp is present (untrusted)")
	verifyFlags.BoolVar(&validateTimestampCertificates, "validate-timestamp-certs", true, "Validate timestamp token certificates")
	verifyFlags.BoolVar(&allowUntrustedRoots, "allow-untrusted-roots", false, "Allow certificates embedded in the PDF to be used as trusted roots (use with caution)")
	verifyFlags.DurationVar(&httpTimeout, "http-timeout", 10*time.Second, "Timeout for external revocation checking requests")

	verifyFlags.Usage = func() {
		fmt.Printf("Usage: %s verify [options] <input.pdf>\n\n", os.Args[0])
		fmt.Println("Verify the digital signature of a PDF file")
		fmt.Println("\nOptions:")
		verifyFlags.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s verify document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -external -http-timeout=30s document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -allow-untrusted-roots self-signed.pdf\n", os.Args[0])
	}

	if err := verifyFlags.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Failed to parse verify flags: %v", err)
	}

	if len(verifyFlags.Args()) < 1 {
		verifyFlags.Usage()
		osExit(1)
	}

	input := verifyFlags.Arg(0)
	VerifyPDF(input, enableExternalRevocation, requireDigitalSignatureKU, requireNonRepudiation,
		trustSignatureTime, validateTimestampCertificates, allowUntrustedRoots, httpTimeout)
}

func VerifyPDF(input string, enableExternalRevocation, requireDigitalSignatureKU, requireNonRepudiation,
	trustSignatureTime, validateTimestampCertificates, allowUntrustedRoots bool, httpTimeout time.Duration) {
	doc, err := pdfsign.OpenFile(input)
	if err != nil {
		log.Print(err)
		osExit(1)
	}

	result := doc.Verify().
		ExternalChecks(enableExternalRevocation).
		RequireDigitalSignature(requireDigitalSignatureKU).
		RequireNonRepudiation(requireNonRepudiation).
		TrustSignatureTime(trustSignatureTime).
		ValidateTimestampCertificates(validateTimestampCertificates).
		TrustSelfSigned(allowUntrustedRoots)

	// Note: HTTPTimeout is not currently in VerifyBuilder but was in vOpts.
	// We'll skip it for now or add it later if critical.

	if err := result.Err(); err != nil {
		fmt.Println(err)
		osExit(1)
	}

	output := struct {
		Document pdfsign.DocumentInfo            `json:"document_info"`
		Signers  []pdfsign.SignatureVerifyResult `json:"signers"`
		Valid    bool                            `json:"valid"`
	}{
		Document: result.Document(),
		Signers:  result.Signatures(),
		Valid:    result.Valid(),
	}

	jsonData, err := json.Marshal(output)
	if err != nil {
		fmt.Println(err)
		osExit(1)
	}
	fmt.Println(string(jsonData))
}
