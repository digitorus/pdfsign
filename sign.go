package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
)

var (
	infoName, infoLocation, infoReason, infoContact, tsa string
	certType                                             string
)

func usage() {
	fmt.Printf("Usage: %s <command> [options] <args>\n\n", os.Args[0])
	fmt.Println("Commands:")
	fmt.Println("  sign    Sign a PDF file")
	fmt.Println("  verify  Verify a PDF signature")
	fmt.Println("")
	fmt.Printf("Use '%s <command> -h' for command-specific help\n", os.Args[0])
	os.Exit(1)
}

func parseCertType(s string) (sign.CertType, error) {
	switch s {
	case sign.CertificationSignature.String():
		return sign.CertificationSignature, nil
	case sign.ApprovalSignature.String():
		return sign.ApprovalSignature, nil
	case sign.UsageRightsSignature.String():
		return sign.UsageRightsSignature, nil
	case sign.TimeStampSignature.String():
		return sign.TimeStampSignature, nil
	default:
		return 0, fmt.Errorf("invalid certType value")
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "sign":
		signCommand()
	case "verify":
		verifyCommand()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		usage()
	}
}

func signCommand() {
	signFlags := flag.NewFlagSet("sign", flag.ExitOnError)

	signFlags.StringVar(&infoName, "name", "", "Name of the signatory")
	signFlags.StringVar(&infoLocation, "location", "", "Location of the signatory")
	signFlags.StringVar(&infoReason, "reason", "", "Reason for signing")
	signFlags.StringVar(&infoContact, "contact", "", "Contact information for signatory")
	signFlags.StringVar(&tsa, "tsa", "https://freetsa.org/tsr", "URL for Time-Stamp Authority")
	signFlags.StringVar(&certType, "certType", "CertificationSignature", "Type of the certificate (CertificationSignature, ApprovalSignature, UsageRightsSignature, TimeStampSignature)")

	signFlags.Usage = func() {
		fmt.Printf("Usage: %s sign [options] <input.pdf> <output.pdf> <certificate.crt> <private_key.key> [chain.crt]\n\n", os.Args[0])
		fmt.Println("Sign a PDF file with a digital signature")
		fmt.Println("\nOptions:")
		signFlags.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s sign -name \"John Doe\" input.pdf output.pdf cert.crt key.key\n", os.Args[0])
		fmt.Printf("  %s sign -certType \"TimeStampSignature\" input.pdf output.pdf\n", os.Args[0])
	}

	if err := signFlags.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Failed to parse sign flags: %v", err)
	}

	if len(signFlags.Args()) < 1 {
		signFlags.Usage()
		os.Exit(1)
	}

	input := signFlags.Arg(0)
	signPDF(input, signFlags.Args())
}

func verifyCommand() {
	verifyFlags := flag.NewFlagSet("verify", flag.ExitOnError)

	// Verification options
	var enableExternalRevocation bool
	var requireDigitalSignatureKU bool
	var requireNonRepudiation bool
	var useSignatureTimeAsFallback bool
	var validateTimestampCertificates bool
	var allowEmbeddedCertificatesAsRoots bool
	var httpTimeout time.Duration

	verifyFlags.BoolVar(&enableExternalRevocation, "external", false, "Enable external OCSP and CRL checking")
	verifyFlags.BoolVar(&requireDigitalSignatureKU, "require-digital-signature", true, "Require Digital Signature key usage in certificates")
	verifyFlags.BoolVar(&requireNonRepudiation, "require-non-repudiation", false, "Require Non-Repudiation key usage in certificates (for highest security)")
	verifyFlags.BoolVar(&useSignatureTimeAsFallback, "use-signature-time-fallback", false, "Use signature time as fallback if no timestamp (untrusted)")
	verifyFlags.BoolVar(&validateTimestampCertificates, "validate-timestamp-certs", true, "Validate timestamp token certificates")
	verifyFlags.BoolVar(&allowEmbeddedCertificatesAsRoots, "allow-embedded-roots", false, "Allow embedded certificates as trusted roots (use with caution)")
	verifyFlags.DurationVar(&httpTimeout, "http-timeout", 10*time.Second, "Timeout for external revocation checking requests")

	verifyFlags.Usage = func() {
		fmt.Printf("Usage: %s verify [options] <input.pdf>\n\n", os.Args[0])
		fmt.Println("Verify the digital signature of a PDF file")
		fmt.Println("\nOptions:")
		verifyFlags.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s verify document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -external -http-timeout=30s document.pdf\n", os.Args[0])
		fmt.Printf("  %s verify -allow-embedded-roots self-signed.pdf\n", os.Args[0])
	}

	if err := verifyFlags.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Failed to parse verify flags: %v", err)
	}

	if len(verifyFlags.Args()) < 1 {
		verifyFlags.Usage()
		os.Exit(1)
	}

	input := verifyFlags.Arg(0)
	verifyPDF(input, enableExternalRevocation, requireDigitalSignatureKU, requireNonRepudiation,
		useSignatureTimeAsFallback, validateTimestampCertificates, allowEmbeddedCertificatesAsRoots, httpTimeout)
}

func verifyPDF(input string, enableExternalRevocation, requireDigitalSignatureKU, requireNonRepudiation,
	useSignatureTimeAsFallback, validateTimestampCertificates, allowEmbeddedCertificatesAsRoots bool, httpTimeout time.Duration) {
	inputFile, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := inputFile.Close(); err != nil {
			log.Printf("Warning: failed to close input file: %v", err)
		}
	}()

	// Create verification options based on command-line flags
	options := verify.DefaultVerifyOptions()
	options.EnableExternalRevocationCheck = enableExternalRevocation
	options.RequireDigitalSignatureKU = requireDigitalSignatureKU
	options.RequireNonRepudiation = requireNonRepudiation
	options.UseSignatureTimeAsFallback = useSignatureTimeAsFallback
	options.ValidateTimestampCertificates = validateTimestampCertificates
	options.AllowEmbeddedCertificatesAsRoots = allowEmbeddedCertificatesAsRoots
	options.HTTPTimeout = httpTimeout

	resp, err := verify.VerifyFileWithOptions(inputFile, options)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func signPDF(input string, args []string) {
	certTypeValue, err := parseCertType(certType)
	if err != nil {
		log.Fatal(err)
	}

	if certTypeValue == sign.TimeStampSignature {
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "TimeStamp signing requires: input.pdf output.pdf\n")
			os.Exit(1)
		}
		output := args[1]
		timeStampPDF(input, output, tsa)
		return
	}

	if len(args) < 4 {
		fmt.Fprintf(os.Stderr, "Signing requires: input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n")
		os.Exit(1)
	}

	output := args[1]
	certPath := args[2]
	keyPath := args[3]
	var chainPath string
	if len(args) > 4 {
		chainPath = args[4]
	}

	cert, pkey, certificateChains := loadCertificatesAndKey(certPath, keyPath, chainPath)

	err = sign.SignFile(input, output, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        infoName,
				Location:    infoLocation,
				Reason:      infoReason,
				ContactInfo: infoContact,
				Date:        time.Now().Local(),
			},
			CertType:   certTypeValue,
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            pkey,
		DigestAlgorithm:   crypto.SHA256,
		Certificate:       cert,
		CertificateChains: certificateChains,
		TSA: sign.TSA{
			URL: tsa,
		},
	})
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + output)
	}
}

func loadCertificatesAndKey(certPath, keyPath, chainPath string) (*x509.Certificate, crypto.Signer, [][]*x509.Certificate) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatal(err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		log.Fatal(errors.New("failed to parse PEM block containing the certificate"))
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		log.Fatal(err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		log.Fatal(errors.New("failed to parse PEM block containing the private key"))
	}

	pkey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	var certificateChains [][]*x509.Certificate
	if chainPath != "" {
		certificateChains = loadCertificateChain(chainPath, cert)
	}

	return cert, pkey, certificateChains
}

func loadCertificateChain(chainPath string, cert *x509.Certificate) [][]*x509.Certificate {
	chainData, err := os.ReadFile(chainPath)
	if err != nil {
		log.Fatal(err)
	}

	certificatePool := x509.NewCertPool()
	certificatePool.AppendCertsFromPEM(chainData)

	certificateChains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: certificatePool,
		CurrentTime:   cert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		log.Fatal(err)
	}

	return certificateChains
}

func timeStampPDF(input, output, tsa string) {
	err := sign.SignFile(input, output, sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.TimeStampSignature,
		},
		DigestAlgorithm: crypto.SHA256,
		TSA: sign.TSA{
			URL: tsa,
		},
	})
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + output)
	}
}
