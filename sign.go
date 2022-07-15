package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"github.com/digitorus/pdfsign/sign"
	"github.com/digitorus/pdfsign/verify"
)

var (
	infoName, infoLocation, infoReason, infoContact, tsa string
)

func usage() {
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Printf("\t%s -name \"Jon Doe\" sign input.pdf output.pdf certificate.crt private_key.key [chain.crt]\n", os.Args[0])
	fmt.Printf("\t%sverify input.pdf\n", os.Args[0])
	os.Exit(1)
}

func main() {
	flag.StringVar(&infoName, "name", "", "Name of the signatory")
	flag.StringVar(&infoLocation, "location", "", "Location of the signatory")
	flag.StringVar(&infoReason, "reason", "", "Reason for signig")
	flag.StringVar(&infoContact, "contact", "", "Contact information for signatory")
	flag.StringVar(&tsa, "tsa", "https://freetsa.org/tsr", "URL for Time-Stamp Authority")

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

		resp, err := verify.File(input_file)
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
		return
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

		certificate_chains := make([][]*x509.Certificate, 0)

		if flag.Arg(5) != "" {
			certificate_pool := x509.NewCertPool()
			if err != nil {
				log.Fatal(err)
			}

			chain_data, err := ioutil.ReadFile(flag.Arg(5))
			if err != nil {
				log.Fatal(err)
			}

			certificate_pool.AppendCertsFromPEM(chain_data)
			certificate_chains, err = cert.Verify(x509.VerifyOptions{
				Intermediates: certificate_pool,
				CurrentTime:   cert.NotBefore,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err != nil {
				log.Fatal(err)
			}
		}

		err = sign.SignFile(input, output, sign.SignData{
			Signature: sign.SignDataSignature{
				Info: sign.SignDataSignatureInfo{
					Name:        infoName,
					Location:    infoLocation,
					Reason:      infoReason,
					ContactInfo: infoContact,
					Date:        time.Now().Local(),
				},
				CertType:   sign.CertificationSignature,
				DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
			},
			Signer:            pkey,
			DigestAlgorithm:   crypto.SHA256,
			Certificate:       cert,
			CertificateChains: certificate_chains,
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
}
