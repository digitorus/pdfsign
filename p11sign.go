package main

import (
	"flag"
	"log"
	"os"
	"time"

	"crypto/x509"
	"io/ioutil"

	"bitbucket.org/digitorus/pdfsign/revocation"
	"bitbucket.org/digitorus/pdfsign/sign"
	"bitbucket.org/digitorus/pdfsign/verify"
	"bitbucket.org/digitorus/pkcs11"
)

func usage() {
	log.Fatal("Usage: sign input.pdf output.pdf pkcs11-password [chain.crt] OR verify input.pdf")
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
		if len(flag.Args()) < 4 {
			usage()
		}

		output := flag.Arg(2)
		if len(output) == 0 {
			usage()
		}

		// pkcs11 key
		lib, err := pkcs11.FindLib("/lib64/libeTPkcs11.so")
		if err != nil {
			log.Fatal(err)
		}

		// Load Library
		ctx := pkcs11.New(lib)
		if ctx == nil {
			log.Fatal("Failed to load library")
		}
		err = ctx.Initialize()
		if err != nil {
			log.Fatal(err)
		}
		// login
		session, err := pkcs11.CreateSession(ctx, 0, flag.Arg(3), false)
		if err != nil {
			log.Fatal(err)
		}
		// select the first certificate
		cert, ckaId, err := pkcs11.GetCert(ctx, session, nil)
		if err != nil {
			log.Fatal(err)
		}

		// private key
		pkey, err := pkcs11.InitPrivateKey(ctx, session, ckaId)
		if err != nil {
			log.Fatal(err)
		}

		certificate_chains := make([][]*x509.Certificate, 0)

		if flag.Arg(4) != "" {
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
			})
			if err != nil {
				log.Fatal(err)
			}
		}

		// TODO: Obtain TSA from certificate or CLI
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
			Signer:            pkey,
			Certificate:       cert,
			CertificateChains: certificate_chains,
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
}
