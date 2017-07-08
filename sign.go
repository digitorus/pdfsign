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

	"bitbucket.org/digitorus/pdfsign/sign"
	"bitbucket.org/digitorus/pdfsign/verify"
)

func usage() {
	log.Fatal("Usage: sign input.pdf output.pdf certificate.crt private_key.key OR verify input.pdf")
}

func main() {
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

	if method == "verify" {
		input_file, err := os.Open(input)
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

	if method == "sign" {
		if len(flag.Args()) < 5 {
			usage()
		}

		output := flag.Arg(2)
		if len(output) == 0 {
			usage()
		}

		certificate_data, err := ioutil.ReadFile(flag.Arg(3))
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

		key_data, err := ioutil.ReadFile(flag.Arg(4))
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

		err = sign.SignFile(input, output, sign.SignData{
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
			Signer:      pkey,
			Certificate: cert,
		})
		if err != nil {
			log.Println(err)
		} else {
			log.Println("Signed PDF written to " + output)
		}
	}
}
