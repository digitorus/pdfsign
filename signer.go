package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"time"

	"bitbucket.org/digitorus/pdfsign/revocation"
	"bitbucket.org/digitorus/pdfsign/sign"
	"bitbucket.org/digitorus/pkcs11"
)

type signer struct {
	certificate       *x509.Certificate
	signer            crypto.Signer
	certificateChains [][]*x509.Certificate
}

func newSigner(crtPath, keyPath, crtChainPath string) (*signer, error) {
	var s signer

	// Set certificate
	certificate_data, err := ioutil.ReadFile(crtPath)
	if err != nil {
		return &s, err
		log.Fatal(err)
	}
	certificate_data_block, _ := pem.Decode(certificate_data)
	if certificate_data_block == nil {
		return &s, errors.New("failed to parse PEM block containing the certificate")
	}
	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		return &s, err
	}
	s.certificate = cert

	// Set key
	key_data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return &s, err
	}
	key_data_block, _ := pem.Decode(key_data)
	if key_data_block == nil {
		return &s, errors.New("failed to parse PEM block containing the private key")
	}
	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		return &s, err
	}
	s.signer = pkey

	certificate_chains, err := getCertificateChains(crtChainPath, cert)
	if err != nil {
		return &s, err
	}
	s.certificateChains = certificate_chains

	return &s, nil
}

func newP11Signer(libPath, pass, crtChainPath string) (*signer, error) {
	var s signer

	// pkcs11 key
	lib, err := pkcs11.FindLib(libPath)
	if err != nil {
		return &s, err
	}

	// Load Library
	ctx := pkcs11.New(lib)
	if ctx == nil {
		return &s, errors.New("Failed to load library")
	}
	err = ctx.Initialize()
	if err != nil {
		return &s, err
	}
	// login
	session, err := pkcs11.CreateSession(ctx, 0, pass, false)
	if err != nil {
		return &s, err
	}
	// select the first certificate
	cert, ckaId, err := pkcs11.GetCert(ctx, session, nil)
	if err != nil {
		return &s, err
	}
	s.certificate = cert

	// private key
	pkey, err := pkcs11.InitPrivateKey(ctx, session, ckaId)
	if err != nil {
		return &s, err
	}
	s.signer = pkey

	certificate_chains, err := getCertificateChains(crtChainPath, cert)
	if err != nil {
		return &s, err
	}
	s.certificateChains = certificate_chains

	return &s, nil
}

func getCertificateChains(crtChainPath string, cert *x509.Certificate) ([][]*x509.Certificate, error) {
	certificate_chains := make([][]*x509.Certificate, 0)
	if crtChainPath == "" {
		return certificate_chains, nil
	}

	chain_data, err := ioutil.ReadFile(crtChainPath)
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

func (s *signer) sign(input, output string, d sign.SignData) error {
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
		Signer:             s.signer,
		Certificate:        s.certificate,
		CertificateChains:  s.certificateChains,
		TSA:                d.TSA,
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
	})
	return err
}
