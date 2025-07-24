package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/digitorus/pdfsign/verify"
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
	inputFile, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := inputFile.Close(); err != nil {
			log.Printf("Warning: failed to close input file: %v", err)
		}
	}()

	options := verify.DefaultVerifyOptions()
	options.EnableExternalRevocationCheck = enableExternalRevocation
	options.RequireDigitalSignatureKU = requireDigitalSignatureKU
	options.RequireNonRepudiation = requireNonRepudiation
	options.TrustSignatureTime = trustSignatureTime
	options.ValidateTimestampCertificates = validateTimestampCertificates
	options.AllowUntrustedRoots = allowUntrustedRoots
	options.HTTPTimeout = httpTimeout

	resp, err := verify.VerifyFileWithOptions(inputFile, options)
	if err != nil {
		fmt.Println(err)
		osExit(1)
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		osExit(1)
	}
	fmt.Println(string(jsonData))
}
