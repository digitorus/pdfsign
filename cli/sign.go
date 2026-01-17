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

	"github.com/digitorus/pdfsign"
)

var (
	InfoName, InfoLocation, InfoReason, InfoContact, TSA string
	CertType                                             string
)

func ParseCertType(s string) (pdfsign.SignatureType, error) {
	switch s {
	case "CertificationSignature":
		return pdfsign.CertificationSignature, nil
	case "ApprovalSignature":
		return pdfsign.ApprovalSignature, nil
	case "DocumentTimestamp":
		return pdfsign.DocumentTimestamp, nil
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
	signFlags.StringVar(&CertType, "certType", "CertificationSignature", "Type of the certificate (CertificationSignature, ApprovalSignature, DocumentTimestamp)")

	signFlags.Usage = func() {
		fmt.Printf("Usage: %s sign [options] <input.pdf> <output.pdf> <certificate.crt> <private_key.key> [chain.crt]\n\n", os.Args[0])
		fmt.Println("Sign a PDF file with a digital signature")
		fmt.Println("\nOptions:")
		signFlags.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s sign -name \"John Doe\" input.pdf output.pdf cert.crt key.key\n", os.Args[0])
		fmt.Printf("  %s sign -certType \"DocumentTimestamp\" input.pdf output.pdf\n", os.Args[0])
	}

	if err := signFlags.Parse(os.Args[2:]); err != nil {
		log.Printf("Failed to parse sign flags: %v", err)
		osExit(1)
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
		log.Println(err)
		osExit(1)
		return
	}

	if certTypeValue == pdfsign.DocumentTimestamp {
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "TimeStamp signing requires: input.pdf output.pdf\n")
			osExit(1)
			return
		}
		output := args[1]
		TimeStampPDF(input, output, TSA)
		return
	}

	if len(args) < 4 {
		fmt.Fprintf(os.Stderr, "Signing requires: input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n")
		osExit(1)
		return
	}

	output := args[1]
	certPath := args[2]
	keyPath := args[3]
	var chainPath string
	if len(args) > 4 {
		chainPath = args[4]
	}

	cert, pkey, certificateChains := LoadCertificatesAndKey(certPath, keyPath, chainPath)

	doc, err := pdfsign.OpenFile(input)
	if err != nil {
		log.Println(err)
		osExit(1)
		return
	}

	doc.Sign(pkey, cert).
		Type(certTypeValue).
		Reason(InfoReason).
		Location(InfoLocation).
		Contact(InfoContact).
		SignerName(InfoName).
		Timestamp(TSA).
		CertificateChains(certificateChains)

	outputFile, err := os.Create(output)
	if err != nil {
		log.Println(err)
		osExit(1)
		return
	}
	defer func() {
		if err := outputFile.Close(); err != nil {
			log.Printf("error closing output file: %v", err)
		}
	}()

	if _, err := doc.Write(outputFile); err != nil {
		log.Println(err)
		osExit(1)
		return
	}
	log.Println("Signed PDF written to " + output)
}

func LoadCertificatesAndKey(certPath, keyPath, chainPath string) (*x509.Certificate, crypto.Signer, [][]*x509.Certificate) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		log.Println(err)
		osExit(1)
		return nil, nil, nil
	}

	certBlock, _ := pem.Decode(certData)
	var cert *x509.Certificate
	if certBlock != nil {
		cert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			log.Println(err)
			osExit(1)
			return nil, nil, nil
		}
	} else if len(certData) > 0 {
		// Try DER
		cert, err = x509.ParseCertificate(certData)
		if err != nil {
			log.Println(err)
			osExit(1)
			return nil, nil, nil
		}
	} else {
		log.Println(errors.New("certificate data is empty"))
		osExit(1)
		return nil, nil, nil
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		log.Println(err)
		osExit(1)
		return nil, nil, nil
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		log.Println(errors.New("failed to parse PEM block containing the private key"))
		osExit(1)
		return nil, nil, nil
	}

	pkey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		log.Println(err)
		osExit(1)
		return nil, nil, nil
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
		log.Println(err)
		osExit(1)
		return nil
	}

	certificatePool := x509.NewCertPool()
	certificatePool.AppendCertsFromPEM(chainData)

	certificateChains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: certificatePool,
		Roots:         certificatePool,
		CurrentTime:   cert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		log.Println(err)
		osExit(1)
		return nil
	}

	return certificateChains
}

func TimeStampPDF(input, output, tsa string) {
	doc, err := pdfsign.OpenFile(input)
	if err != nil {
		log.Println(err)
		osExit(1)
		return
	}

	doc.Timestamp(tsa)

	outputFile, err := os.Create(output)
	if err != nil {
		log.Println(err)
		osExit(1)
		return
	}
	defer func() {
		if err := outputFile.Close(); err != nil {
			log.Printf("error closing output file: %v", err)
		}
	}()

	if _, err := doc.Write(outputFile); err != nil {
		log.Println(err)
		osExit(1)
		return
	}
	log.Println("Signed PDF written to " + output)
}
