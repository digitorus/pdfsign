package sign

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"bitbucket.org/digitorus/pdfsign/revocation"

	"golang.org/x/crypto/ocsp"
)

func embedOCSPRevocationStatus(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return err
	}

	ocspUrl := fmt.Sprintf("%s/%s", strings.TrimRight(cert.OCSPServer[0], "/"),
		base64.StdEncoding.EncodeToString(req))
	resp, err := http.Get(ocspUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// check if we got a valid OCSP response
	_, err = ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return err
	}

	i.AddOCSP(body)
	return nil
}

// embedCRLRevocationStatus requires an issuer as it needs to implement the
// the interface, a nil argment might be given if the issuer is not known.
func embedCRLRevocationStatus(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
	resp, err := http.Get(cert.CRLDistributionPoints[0])
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// TODO: verify crl and certificate before embedding
	i.AddCRL(body)
	return nil
}

func embedRevocationStatus(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
	// For each certificate a revoction status needs to be included, this can be done
	// by embedding a CRL or OCSP response. In most cases an OCSP response is smaller
	// to embed in the document but and empty CRL (often seen of dediced high volume
	// hirachies) can be smaller.
	//
	// There have been some reports that the usage of a CRL would result in a better
	// compatibilty.
	//
	// TODO: Find and embed link about compatibilty
	// TODO: Implement revocation status caching (required for higher volume signing)

	// using an OCSP server
	if len(cert.OCSPServer) > 0 {
		embedOCSPRevocationStatus(cert, issuer, i)
		return nil
	}

	// using a crl
	if len(cert.CRLDistributionPoints) > 0 {
		embedCRLRevocationStatus(cert, issuer, i)
		return nil
	}

	return errors.New("certificate contains no information to check status")
}
