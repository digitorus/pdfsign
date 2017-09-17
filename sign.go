package main

import (
	"flag"
	"log"
	"os"
	"time"

	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"fmt"

	"bitbucket.org/digitorus/pdfsign/revocation"
	"bitbucket.org/digitorus/pdfsign/sign"
	"bitbucket.org/digitorus/pdfsign/verify"
)

// usage is a usage function for the flags package.
func usage() {
	fmt.Fprintf(os.Stderr, "Pdfsign is a tool to sign and verifyPDF PDF digital signatures\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "\tpdfsign command [arguments]\n\n")
	fmt.Fprintf(os.Stderr, "The commands are:\n\n")
	fmt.Fprintf(os.Stderr, "\tsign \t\tsign single PDF document\n")
	fmt.Fprintf(os.Stderr, "\tverifyPDF \t\tverifyPDF signature of single PDF document\n")
	fmt.Fprintf(os.Stderr, "\tserve \t\tserve web API with signing capabilities. API documentation url\n")
	fmt.Fprintf(os.Stderr, "\twatch \t\tautomatically sign PDF files inside a folder\n")
	fmt.Fprintf(os.Stderr, "\n\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	// if no flags provided print usage
	if len(os.Args) == 1 {
		usage()
		return
	}

	switch os.Args[1] {
	case "sign":
		simpleSign()
	case "verifyPDF":
		verifyPDF()
	case "serve":
	case "watch":
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}
}

func verifyPDF() {
	verifyCommand := flag.NewFlagSet("verifyPDF", flag.ExitOnError)
	input := verifyCommand.String("in", "", "")

	input_file, err := os.Open(*input)
	if err != nil {
		log.Fatal(err)
	}
	defer input_file.Close()

	resp, err := verify.Verify(input_file)
	log.Println(resp)
	if err != nil {
		log.Println(err)
	}
}

func simpleSign() {
	signCommand := flag.NewFlagSet("sign", flag.ExitOnError)
	input := signCommand.String("in", "", "Input PDF file")
	output := signCommand.String("out", "", "Output PDF file")
	crt := signCommand.String("crt", "", "Certificate")
	key := signCommand.String("key", "", "Private key")
	crtChain := signCommand.String("chain", "", "Certificate chain")
	help := signCommand.Bool("help", false, "Show this help")

	signCommand.Parse(os.Args[2:])
	usageText := `usageText: pdfsign sign -in input.pdf -out output.pdf -crt certificate.crt -key private_key.key [-chain chain.crt]\n\n")
Description
`
	if *help == true {
		fmt.Println(usageText)
		signCommand.PrintDefaults()
		return
	}

	if signCommand.Parsed() == false || *input == "" || *output == "" || *crt == "" || *key == "" {
		fmt.Println(usageText)
		signCommand.PrintDefaults()
		os.Exit(1)
	}

	certificate_data, err := ioutil.ReadFile(*crt)
	if err != nil {
		log.Fatal(err)
	}
	certificate_data_block, _ := pem.Decode(certificate_data)
	if certificate_data_block == nil {
		log.Fatal(errors.New("failed to parse PEM block containing the certificate"))
	}
	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	key_data, err := ioutil.ReadFile(*key)
	if err != nil {
		log.Fatal(err)
	}
	key_data_block, _ := pem.Decode(key_data)
	if key_data_block == nil {
		log.Fatal(errors.New("failed to parse PEM block containing the private key"))
	}
	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	certificate_chains, err := getCertificateChains(*crtChain, cert)
	if err != nil {
		log.Fatal(err)
	}

	var data sign.SignData
	data.Signer = pkey
	data.Certificate = cert
	data.CertificateChains = certificate_chains
	signWithConfig(*input, *output, data)
}

func p11sign() {
	//if len(flag.Args()) < 2 {
	//	usage()
	//}
	//
	//method := flag.Arg(0)
	//if method != "sign" && method != "verifyPDF" {
	//	usage()
	//}
	//
	//input := flag.Arg(1)
	//if len(input) == 0 {
	//	usage()
	//}
	//
	//if method == "verifyPDF" {
	//	input_file, err := os.Open(input)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	defer input_file.Close()
	//
	//	resp, err := verify.Verify(input_file)
	//	log.Println(resp)
	//	if err != nil {
	//		log.Println(err)
	//	}
	//}
	//
	//if method == "sign" {
	//	if len(flag.Args()) < 4 {
	//		usage()
	//	}
	//
	//	output := flag.Arg(2)
	//	if len(output) == 0 {
	//		usage()
	//	}
	//
	//	// pkcs11 key
	//	lib, err := pkcs11.FindLib("/lib64/libeTPkcs11.so")
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//
	//	// Load Library
	//	ctx := pkcs11.New(lib)
	//	if ctx == nil {
	//		log.Fatal("Failed to load library")
	//	}
	//	err = ctx.Initialize()
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	// login
	//	session, err := pkcs11.CreateSession(ctx, 0, flag.Arg(3), false)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//	// select the first certificate
	//	cert, ckaId, err := pkcs11.GetCert(ctx, session, nil)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
	//
	//	// private key
	//	pkey, err := pkcs11.InitPrivateKey(ctx, session, ckaId)
	//	if err != nil {
	//		log.Fatal(err)
	//	}
}

func getCertificateChains(crtChain string, cert *x509.Certificate) ([][]*x509.Certificate, error) {
	certificate_chains := make([][]*x509.Certificate, 0)
	if crtChain == "" {
		return certificate_chains, nil
	}

	chain_data, err := ioutil.ReadFile(crtChain)
	if err != nil {
		log.Fatal(err)
	}
	certificate_pool := x509.NewCertPool()
	certificate_pool.AppendCertsFromPEM(chain_data)
	certificate_chains, err = cert.Verify(x509.VerifyOptions{
		Intermediates: certificate_pool,
		CurrentTime:   cert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})

	return certificate_chains, err
}

func signWithConfig(input, output string, data sign.SignData) {
	err := sign.SignFile(input, output, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        "Jeroen Bobbeldijk",
				Location:    "Rotterdam",
				Reason:      "Test",
				ContactInfo: "Geen",
				Date:        time.Now().Local(),
			},
			CertType: 2,
			Approval: false,
		},
		Signer:            data.Signer,
		Certificate:       data.Certificate,
		CertificateChains: data.CertificateChains,
		TSA: sign.TSA{
			URL: "http://aatl-timestamp.globalsign.com/tsa/aohfewat2389535fnasgnlg5m23",
		},
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
	})
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + output)
	}
}
