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

	"crypto"

	"bitbucket.org/digitorus/pdfsign/config"
	"bitbucket.org/digitorus/pdfsign/revocation"
	"bitbucket.org/digitorus/pdfsign/sign"
	"bitbucket.org/digitorus/pdfsign/verify"
	"bitbucket.org/digitorus/pkcs11"
)

// usage is a usage function for the flags package.
func usage() {
	fmt.Fprintf(os.Stderr, "Pdfsign is a tool to sign and verify PDF digital signatures\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n\n")
	fmt.Fprintf(os.Stderr, "\tpdfsign command [arguments]\n\n")
	fmt.Fprintf(os.Stderr, "The commands are:\n\n")
	fmt.Fprintf(os.Stderr, "\tsign \t\tsign single PDF document\n")
	fmt.Fprintf(os.Stderr, "\tverify \t\tverify signature of single PDF document\n")
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
	case "verify":
		verifyPDF()
	case "serve":
	case "watch":
	default:
		fmt.Printf("%q is not valid command.\n", os.Args[1])
		os.Exit(2)
	}
}

func verifyPDF() {
	verifyCommand := flag.NewFlagSet("verify", flag.ExitOnError)
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

func getSignDataFlags(f *flag.FlagSet) sign.SignData {
	// Signature info
	name := f.String("info-name", config.Settings.Info.Name, "Signature info name")
	location := f.String("info-location", config.Settings.Info.Location, "Signature info location")
	reason := f.String("info-reason", config.Settings.Info.Reason, "Signature info reason")
	contact := f.String("info-contact", config.Settings.Info.ContactInfo, "Signature info contact")
	// Signature other
	approval := f.Bool("approval", false, "Approval")
	certType := f.Uint("type", 0, "Certificate type")

	// TSA
	tsaUrl := f.String("tsa-url", "", "tsaUrl")
	tsaUsername := f.String("tsa-username", "", "tsaUsername")
	tsaPassword := f.String("tsa-password", "", "tsaPassword")

	var sd sign.SignData
	sd.Signature.Info.Name = *name
	sd.Signature.Info.Location = *location
	sd.Signature.Info.Reason = *reason
	sd.Signature.Info.ContactInfo = *contact
	sd.Signature.CertType = uint32(*certType)
	sd.Signature.Approval = *approval
	sd.TSA.URL = *tsaUrl
	sd.TSA.Username = *tsaUsername
	sd.TSA.Password = *tsaPassword
	return sd
}

func simpleSign() {
	signCommand := flag.NewFlagSet("sign", flag.ExitOnError)
	configPath := signCommand.String("config", "", "Path to config file")
	signCommand.Parse(os.Args[2:])
	if *configPath != "" {
		config.Read(*configPath)
	}

	inputPath := signCommand.String("in", "", "Input PDF file")
	outputPath := signCommand.String("out", "", "Output PDF file")
	crtPath := signCommand.String("crt", "", "Certificate")
	keyPath := signCommand.String("key", "", "Private key")
	crtChainPath := signCommand.String("chain", "", "Certificate chain")
	help := signCommand.Bool("help", false, "Show this help")
	signData := getSignDataFlags(signCommand)
	signCommand.Parse(os.Args[2:])

	usageText := `usage: pdfsign sign -in input.pdf -out output.pdf -crt certificate.crt -key private_key.key [-chain chain.crt]")
Description
`
	if *help == true {
		fmt.Println(usageText)
		signCommand.PrintDefaults()
		return
	}

	if signCommand.Parsed() == false || *inputPath == "" || *outputPath == "" || *crtPath == "" || *keyPath == "" {
		fmt.Println(usageText)
		signCommand.PrintDefaults()
		os.Exit(2)
	}

	cert, signer, err := getCertSignerPair(*crtPath, *keyPath)
	if err != nil {
		log.Fatal(err)
	}

	certificate_chains, err := getCertificateChains(*crtChainPath, cert)
	if err != nil {
		log.Fatal(err)
	}

	signData.Signer = signer
	signData.Certificate = cert
	signData.CertificateChains = certificate_chains
	if err := signWithConfig(*inputPath, *outputPath, signData); err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + *outputPath)
	}
}

func getCertSignerPair(crtPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	var certificate *x509.Certificate
	var signer crypto.Signer

	// Set certificate
	certificate_data, err := ioutil.ReadFile(crtPath)
	if err != nil {
		return certificate, signer, err
		log.Fatal(err)
	}
	certificate_data_block, _ := pem.Decode(certificate_data)
	if certificate_data_block == nil {
		return certificate, signer, errors.New("failed to parse PEM block containing the certificate")
	}
	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		return certificate, signer, err
	}
	certificate = cert

	// Set key
	key_data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return certificate, signer, err
	}
	key_data_block, _ := pem.Decode(key_data)
	if key_data_block == nil {
		return certificate, signer, errors.New("failed to parse PEM block containing the private key")
	}
	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		return certificate, signer, err
	}
	signer = pkey

	return certificate, signer, nil
}

func p11sign() {
	signCommand := flag.NewFlagSet("sign", flag.ExitOnError)
	configPath := signCommand.String("config", "", "Path to config file")
	signCommand.Parse(os.Args[2:])
	if *configPath != "" {
		config.Read(*configPath)
	}

	input := signCommand.String("in", "", "Input PDF file")
	output := signCommand.String("out", "", "Output PDF file")
	libPath := signCommand.String("lib", "", "Path to PKCS11 library")
	pass := signCommand.String("pass", "", "PKCS11 password")
	crtChain := signCommand.String("chain", "", "Certificate chain")
	help := signCommand.Bool("help", false, "Show this help")

	signCommand.Parse(os.Args[2:])
	usageText := `Usage: pdfsign sign -in input.pdf -out output.pdf -pass pkcs11-password [-chain chain.crt]")

Description

`
	if *help == true {
		fmt.Println(usageText)
		signCommand.PrintDefaults()
		return
	}

	if signCommand.Parsed() == false || *input == "" || *output == "" || *pass == "" {
		fmt.Println(usageText)
		signCommand.PrintDefaults()
		os.Exit(2)
	}

	cert, signer, err := getP11CertSignerPair(*libPath, *pass)
	if err != nil {
		log.Fatal(err)
	}

	certificate_chains, err := getCertificateChains(*crtChain, cert)
	if err != nil {
		log.Fatal(err)
	}

	var data sign.SignData
	data.Certificate = cert
	data.Signer = signer
	data.CertificateChains = certificate_chains
	if err := signWithConfig(*input, *output, data); err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + *output)
	}
}

func getP11CertSignerPair(libPath, pass string) (*x509.Certificate, crypto.Signer, error) {
	var certificate *x509.Certificate
	var signer crypto.Signer

	// pkcs11 key
	lib, err := pkcs11.FindLib(libPath)
	if err != nil {
		return certificate, signer, err
	}

	// Load Library
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return certificate, signer, errors.New("Failed to load library")
	}
	err = ctx.Initialize()
	if err != nil {
		return certificate, signer, err
	}
	// login
	session, err := pkcs11.CreateSession(ctx, 0, pass, false)
	if err != nil {
		return certificate, signer, err
	}
	// select the first certificate
	cert, ckaId, err := pkcs11.GetCert(ctx, session, nil)
	if err != nil {
		return certificate, signer, err
	}
	certificate = cert

	// private key
	pkey, err := pkcs11.InitPrivateKey(ctx, session, ckaId)
	if err != nil {
		return certificate, signer, err
	}
	signer = pkey

	return certificate, signer, nil
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

func signWithConfig(input, output string, d sign.SignData) error {
	err := sign.SignFile(input, output, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        d.Signature.Info.Name,
				Location:    d.Signature.Info.Location,
				Reason:      d.Signature.Info.Reason,
				ContactInfo: d.Signature.Info.ContactInfo,
				Date:        time.Now().Local(),
			},
			CertType: d.Signature.CertType,
			Approval: d.Signature.Approval,
		},
		Signer:             d.Signer,
		Certificate:        d.Certificate,
		CertificateChains:  d.CertificateChains,
		TSA:                d.TSA,
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
	})
	return err
}
