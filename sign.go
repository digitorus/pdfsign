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
	signFlags                                            *flag.FlagSet
)

func setupSignFlags() *flag.FlagSet {
	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	flags.StringVar(&infoName, "name", "", "Name of the signatory")
	flags.StringVar(&infoLocation, "location", "", "Location of the signatory")
	flags.StringVar(&infoReason, "reason", "", "Reason for signing")
	flags.StringVar(&infoContact, "contact", "", "Contact information for signatory")
	flags.StringVar(&tsa, "tsa", "https://freetsa.org/tsr", "URL for Time-Stamp Authority")
	flags.StringVar(&certType, "certType", "CertificationSignature", "Type of the certificate (CertificationSignature, ApprovalSignature, UsageRightsSignature, TimeStampSignature)")
	return flags
}

func usage() {
	signFlags := setupSignFlags()
	signFlags.PrintDefaults()
	fmt.Println("\nExample usage:")
	fmt.Printf("\t%s sign -name \"Jon Doe\" input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n", os.Args[0])
	fmt.Printf("\t%s sign -certType \"CertificationSignature\" -name \"Jon Doe\" input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n", os.Args[0])
	fmt.Printf("\t%s sign -certType \"TimeStampSignature\" input.pdf output.pdf\n", os.Args[0])
	fmt.Printf("\t%s sign -certType \"TimeStampSignature\" -tsa \"https://custom-tsa.example.com/tsr\" input.pdf output.pdf\n", os.Args[0])
	fmt.Printf("\t%s verify input.pdf\n", os.Args[0])
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
	// Get the subcommand
	if len(os.Args) < 2 {
		usage()
	}

	method := os.Args[1]
	if method != "sign" && method != "verify" {
		usage()
	}

	// Now parse flags for the specific subcommand
	if method == "sign" {
		signFlags = setupSignFlags()
		signFlags.Parse(os.Args[2:])

		if len(signFlags.Args()) < 2 {
			usage()
		}

		input := signFlags.Arg(0)
		if len(input) == 0 {
			usage()
		}

		signPDF(input)
	} else {
		// For verify, we don't need flags, just the input file
		if len(os.Args) < 3 {
			usage()
		}
		input := os.Args[2]
		verifyPDF(input)
	}
}

func verifyPDF(input string) {
	inputFile, err := os.Open(input)
	if err != nil {
		log.Fatal(err)
	}
	defer inputFile.Close()

	resp, err := verify.File(inputFile)
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

func signPDF(input string) {
	certTypeValue, err := parseCertType(certType)
	if err != nil {
		log.Fatal(err)
	}

	if certTypeValue == sign.TimeStampSignature {
		if len(signFlags.Args()) < 2 {
			usage()
		}

		output := signFlags.Arg(1)
		if len(output) == 0 {
			usage()
		}
		timeStampPDF(input, output, tsa)
		return
	}

	// For other signature types, we need certificate and key files
	if len(signFlags.Args()) < 5 {
		usage()
	}

	output := signFlags.Arg(1)
	if len(output) == 0 {
		usage()
	}

	cert, pkey, certificateChains := loadCertificatesAndKey(signFlags.Arg(2), signFlags.Arg(3), signFlags.Arg(4))

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
