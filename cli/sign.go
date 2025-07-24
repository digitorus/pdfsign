package cli

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/digitorus/pdfsign/sign"
)

var (
	InfoName, InfoLocation, InfoReason, InfoContact, TSA string
	CertType                                             string
)

func ParseCertType(s string) (sign.CertType, error) {
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

func SignCommand() {
	signFlags := flag.NewFlagSet("sign", flag.ExitOnError)

	signFlags.StringVar(&InfoName, "name", "", "Name of the signatory")
	signFlags.StringVar(&InfoLocation, "location", "", "Location of the signatory")
	signFlags.StringVar(&InfoReason, "reason", "", "Reason for signing")
	signFlags.StringVar(&InfoContact, "contact", "", "Contact information for signatory")
	signFlags.StringVar(&TSA, "tsa", "https://freetsa.org/tsr", "URL for Time-Stamp Authority")
	signFlags.StringVar(&CertType, "certType", "CertificationSignature", "Type of the certificate (CertificationSignature, ApprovalSignature, UsageRightsSignature, TimeStampSignature)")

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
		osExit(1)
	}

	input := signFlags.Arg(0)
	SignPDF(input, signFlags.Args())
}

// SignPDFFuncType defines the function signature for SignPDF
var SignPDF = signPDFImpl

func signPDFImpl(input string, args []string) {
	certTypeValue, err := ParseCertType(CertType)
	if err != nil {
		log.Fatal(err)
	}

	if certTypeValue == sign.TimeStampSignature {
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "TimeStamp signing requires: input.pdf output.pdf\n")
			osExit(1)
		}
		output := args[1]
		TimeStampPDF(input, output, TSA)
		return
	}

	if len(args) < 4 {
		fmt.Fprintf(os.Stderr, "Signing requires: input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n")
		osExit(1)
	}

	output := args[1]
	certPath := args[2]
	keyPath := args[3]
	var chainPath string
	if len(args) > 4 {
		chainPath = args[4]
	}

	cert, pkey, certificateChains := LoadCertificatesAndKey(certPath, keyPath, chainPath)

	err = sign.SignFile(input, output, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        InfoName,
				Location:    InfoLocation,
				Reason:      InfoReason,
				ContactInfo: InfoContact,
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
			URL: TSA,
		},
	})
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + output)
	}
}

func LoadCertificatesAndKey(certPath, keyPath, chainPath string) (*x509.Certificate, crypto.Signer, [][]*x509.Certificate) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Fatal(err)
	}

	certBlock, _ := pem.Decode(certData)
	var cert *x509.Certificate
	if certBlock != nil {
		cert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	} else if len(certData) > 0 {
		// Try DER
		cert, err = x509.ParseCertificate(certData)
		if err != nil {
			log.Fatal(errors.New("failed to parse certificate as PEM or DER"))
		}
	} else {
		log.Fatal(errors.New("certificate data is empty"))
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
		certificateChains = LoadCertificateChain(chainPath, cert)
	}

	return cert, pkey, certificateChains
}

func LoadCertificateChain(chainPath string, cert *x509.Certificate) [][]*x509.Certificate {
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

func TimeStampPDF(input, output, tsa string) {
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
