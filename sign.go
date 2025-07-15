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
	flag.PrintDefaults()
	fmt.Println("\nExample usage:")
	fmt.Printf("\t%s -name \"Jon Doe\" sign input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n", os.Args[0])
	fmt.Printf("\t%s -certType \"CertificationSignature\" -name \"Jon Doe\" sign input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n", os.Args[0])
	fmt.Printf("\t%s -certType \"TimeStampSignature\" input.pdf output.pdf\n", os.Args[0])
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
	flag.StringVar(&infoName, "name", "", "Name of the signatory")
	flag.StringVar(&infoLocation, "location", "", "Location of the signatory")
	flag.StringVar(&infoReason, "reason", "", "Reason for signing")
	flag.StringVar(&infoContact, "contact", "", "Contact information for signatory")
	flag.StringVar(&tsa, "tsa", "https://freetsa.org/tsr", "URL for Time-Stamp Authority")
	flag.StringVar(&certType, "certType", "CertificationSignature", "Type of the certificate (CertificationSignature, ApprovalSignature, UsageRightsSignature, TimeStampSignature)")

	flag.Parse()

	if len(flag.Args()) < 2 {
		usage()
	}

	method := flag.Arg(0)
	if method != "sign" && method != "verify" {
		usage()
	}

	input := flag.Arg(1)
	if len(input) == 0 {
		usage()
	}

	switch method {
	case "verify":
		verifyPDF(input)
	case "sign":
		signPDF(input)
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
		output := flag.Arg(2)
		if len(output) == 0 {
			usage()
		}
		timeStampPDF(input, output, tsa)
		return
	}

	if len(flag.Args()) < 5 {
		usage()
	}

	output := flag.Arg(2)
	if len(output) == 0 {
		usage()
	}

	cert, pkey, certificateChains := loadCertificatesAndKey(flag.Arg(3), flag.Arg(4), flag.Arg(5))

	result, err := sign.SignFile(input, output, sign.SignData{
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
		if result != nil {
			log.Printf("Document Hash (SHA256): %s", result.DocumentHashSHA256)
			log.Printf("Signature Hash (SHA256): %s", result.SignatureHashSHA256)
			log.Printf("Certificate Hash (SHA256): %s", result.CertificateHashSHA256)
			log.Printf("Certificate Details:")
			log.Printf("  Subject CN: %s", result.CertificateDetails.CommonName)
			log.Printf("  Subject C: %v", result.CertificateDetails.Country)
			log.Printf("  Subject O: %v", result.CertificateDetails.Organization)
			log.Printf("  Subject OU: %v", result.CertificateDetails.OrganizationalUnit)
			log.Printf("  Serial Number: %s", result.CertificateDetails.SerialNumber)
			log.Printf("  Issuer CN: %s", result.CertificateDetails.Issuer.CommonName)
			log.Printf("  Issuer C: %v", result.CertificateDetails.Issuer.Country)
			log.Printf("  Issuer O: %v", result.CertificateDetails.Issuer.Organization)
			log.Printf("  Issuer OU: %v", result.CertificateDetails.Issuer.OrganizationalUnit)
			log.Printf("  Not Before: %s", result.CertificateDetails.NotBefore.Format(time.RFC3339))
			log.Printf("  Not After: %s", result.CertificateDetails.NotAfter.Format(time.RFC3339))
			log.Printf("  Public Key Algorithm: %s", result.CertificateDetails.PublicKeyAlgorithm)
			log.Printf("  Signature Algorithm: %s", result.CertificateDetails.SignatureAlgorithm)
		}
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
	result, err := sign.SignFile(input, output, sign.SignData{
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
		if result != nil {
			log.Printf("Document Hash (SHA256): %s", result.DocumentHashSHA256)
			log.Printf("Signature Hash (SHA256): %s", result.SignatureHashSHA256)
			if result.CertificateHashSHA256 != "" {
				log.Printf("Certificate Hash (SHA256): %s", result.CertificateHashSHA256)
			}
		}
	}
}
