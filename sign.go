package main

import (
	"flag"
	"log"
	"os"

	"fmt"

	"bitbucket.org/digitorus/pdfsign/config"
	"bitbucket.org/digitorus/pdfsign/sign"
	"bitbucket.org/digitorus/pdfsign/verify"
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

	s, err := newSigner(*crtPath, *keyPath, *crtChainPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := s.sign(*inputPath, *outputPath, signData); err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + *outputPath)
	}
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
	crtChainPath := signCommand.String("chain", "", "Certificate chain")
	help := signCommand.Bool("help", false, "Show this help")
	signData := getSignDataFlags(signCommand)
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

	s, err := newP11Signer(*libPath, *pass, *crtChainPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := s.sign(*input, *output, signData); err != nil {
		log.Println(err)
	} else {
		log.Println("Signed PDF written to " + *output)
	}
}
