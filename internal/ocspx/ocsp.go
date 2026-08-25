// Package ocspx adds ML-DSA response support around golang.org/x/crypto/ocsp.
// The upstream package can encode SHA-512 CertIDs but, as of x/crypto v0.55.0,
// only recognizes RSA and ECDSA response signatures.
package ocspx

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	oidBasicResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidSHA1          = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidMLDSA44       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type responseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytes `asn1:"explicit,tag:0,optional"`
}

type responseBytes struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponse struct {
	TBSResponseData    responseData
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseData struct {
	Raw            asn1.RawContent
	Version        int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID asn1.RawValue
	ProducedAt     time.Time `asn1:"generalized"`
	Responses      []singleResponse
}

type singleResponse struct {
	CertID           certID
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfo      `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type revokedInfo struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// CreateResponse creates a directly-issued OCSP response. Classical keys are
// delegated to x/crypto/ocsp; ML-DSA uses pure-mode signatures and parameterless
// AlgorithmIdentifiers as specified for ML-DSA in X.509.
func CreateResponse(issuer *x509.Certificate, template ocsp.Response, priv crypto.Signer) ([]byte, error) {
	public, ok := priv.Public().(*mldsa.PublicKey)
	if !ok {
		return ocsp.CreateResponse(issuer, issuer, template, priv)
	}

	_, signatureOID, ok := mlDSAAlgorithm(public)
	if !ok {
		return nil, fmt.Errorf("unsupported ML-DSA parameter set %s", public.Parameters())
	}

	issuerHash := template.IssuerHash
	if issuerHash == 0 {
		issuerHash = crypto.SHA512
	}
	nameHash, keyHash, hashOID, err := issuerHashes(issuer, issuerHash)
	if err != nil {
		return nil, err
	}

	single := singleResponse{
		CertID: certID{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue},
			NameHash:      nameHash,
			IssuerKeyHash: keyHash,
			SerialNumber:  template.SerialNumber,
		},
		ThisUpdate:       template.ThisUpdate.UTC(),
		NextUpdate:       template.NextUpdate.UTC(),
		SingleExtensions: template.ExtraExtensions,
	}
	switch template.Status {
	case ocsp.Good:
		single.Good = true
	case ocsp.Unknown:
		single.Unknown = true
	case ocsp.Revoked:
		single.Revoked = revokedInfo{RevocationTime: template.RevokedAt.UTC(), Reason: asn1.Enumerated(template.RevocationReason)}
	default:
		return nil, fmt.Errorf("unsupported OCSP status %d", template.Status)
	}

	tbs := responseData{
		RawResponderID: asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: issuer.RawSubject},
		ProducedAt:     time.Now().Truncate(time.Minute).UTC(),
		Responses:      []singleResponse{single},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	signature, err := priv.Sign(rand.Reader, tbsDER, &mldsa.Options{})
	if err != nil {
		return nil, err
	}
	basicDER, err := asn1.Marshal(basicResponse{
		TBSResponseData:    tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureOID},
		Signature:          asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(responseASN1{
		Status: 0,
		Response: responseBytes{
			ResponseType: oidBasicResponse,
			Response:     basicDER,
		},
	})
}

// ParseResponseForCert preserves x/crypto/ocsp behavior and adds a strict
// fallback for ML-DSA-signed responses, including CertID issuer binding and
// parameterless ML-DSA AlgorithmIdentifier validation.
func ParseResponseForCert(der []byte, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	response, err := ocsp.ParseResponseForCert(der, cert, issuer)
	if err == nil {
		return response, nil
	}
	if issuer == nil || issuer.PublicKeyAlgorithm != x509.MLDSA {
		return nil, err
	}

	outer, basic, parseErr := parseBasicResponse(der)
	if parseErr != nil {
		return nil, parseErr
	}
	algorithm, ok := signatureAlgorithm(basic.SignatureAlgorithm)
	if !ok {
		return nil, err
	}

	var signingCertificate = issuer
	if len(basic.Certificates) > 0 {
		signingCertificate, parseErr = x509.ParseCertificate(basic.Certificates[0].FullBytes)
		if parseErr != nil {
			return nil, parseErr
		}
		if parseErr = signingCertificate.CheckSignatureFrom(issuer); parseErr != nil {
			return nil, fmt.Errorf("bad OCSP responder certificate: %w", parseErr)
		}
	}
	if parseErr = signingCertificate.CheckSignature(algorithm, basic.TBSResponseData.Raw, basic.Signature.RightAlign()); parseErr != nil {
		return nil, fmt.Errorf("bad ML-DSA OCSP signature: %w", parseErr)
	}

	matched, parseErr := matchingCertID(basic.TBSResponseData.Responses, cert)
	if parseErr != nil {
		return nil, parseErr
	}
	hash, ok := hashFromOID(matched.HashAlgorithm.Algorithm)
	if !ok {
		return nil, errors.New("unsupported OCSP CertID hash algorithm")
	}
	nameHash, keyHash, _, parseErr := issuerHashes(issuer, hash)
	if parseErr != nil {
		return nil, parseErr
	}
	if !bytes.Equal(matched.NameHash, nameHash) || !bytes.Equal(matched.IssuerKeyHash, keyHash) {
		return nil, errors.New("OCSP CertID does not match issuer")
	}

	// Remove embedded certificates before asking x/crypto/ocsp to decode the
	// response fields; otherwise its RSA/ECDSA-only verifier rejects ML-DSA.
	basic.Certificates = nil
	outer.Response.Response, parseErr = asn1.Marshal(basic)
	if parseErr != nil {
		return nil, parseErr
	}
	unsignedDER, parseErr := asn1.Marshal(outer)
	if parseErr != nil {
		return nil, parseErr
	}
	response, parseErr = ocsp.ParseResponseForCert(unsignedDER, cert, nil)
	if parseErr != nil {
		return nil, parseErr
	}
	response.Raw = der
	response.Certificate = nil
	if signingCertificate != issuer {
		response.Certificate = signingCertificate
	}
	response.SignatureAlgorithm = algorithm
	return response, nil
}

func parseBasicResponse(der []byte) (responseASN1, basicResponse, error) {
	var outer responseASN1
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 {
		return outer, basicResponse{}, errors.New("invalid OCSP response")
	}
	if outer.Status != 0 || !outer.Response.ResponseType.Equal(oidBasicResponse) {
		return outer, basicResponse{}, errors.New("OCSP response is not successful basic OCSP")
	}
	var basic basicResponse
	rest, err = asn1.Unmarshal(outer.Response.Response, &basic)
	if err != nil || len(rest) != 0 {
		return outer, basic, errors.New("invalid basic OCSP response")
	}
	return outer, basic, nil
}

func matchingCertID(responses []singleResponse, cert *x509.Certificate) (certID, error) {
	for _, response := range responses {
		if cert == nil || response.CertID.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return response.CertID, nil
		}
	}
	return certID{}, errors.New("OCSP response does not match certificate")
}

func issuerHashes(issuer *x509.Certificate, hash crypto.Hash) ([]byte, []byte, asn1.ObjectIdentifier, error) {
	oid, ok := hashOID(hash)
	if !ok || !hash.Available() {
		return nil, nil, nil, fmt.Errorf("unsupported issuer hash %s", hash)
	}
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return nil, nil, nil, err
	}
	h := hash.New()
	h.Write(issuer.RawSubject)
	nameHash := h.Sum(nil)
	h.Reset()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	return nameHash, h.Sum(nil), oid, nil
}

func hashOID(hash crypto.Hash) (asn1.ObjectIdentifier, bool) {
	switch hash {
	case crypto.SHA1:
		return oidSHA1, true
	case crypto.SHA256:
		return oidSHA256, true
	case crypto.SHA384:
		return oidSHA384, true
	case crypto.SHA512:
		return oidSHA512, true
	default:
		return nil, false
	}
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		if candidate, _ := hashOID(hash); oid.Equal(candidate) {
			return hash, true
		}
	}
	return 0, false
}

func mlDSAAlgorithm(public *mldsa.PublicKey) (x509.SignatureAlgorithm, asn1.ObjectIdentifier, bool) {
	switch public.Parameters() {
	case mldsa.MLDSA44():
		return x509.MLDSA44, oidMLDSA44, true
	case mldsa.MLDSA65():
		return x509.MLDSA65, oidMLDSA65, true
	case mldsa.MLDSA87():
		return x509.MLDSA87, oidMLDSA87, true
	default:
		return 0, nil, false
	}
}

func signatureAlgorithm(identifier pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, bool) {
	if len(identifier.Parameters.FullBytes) != 0 {
		return 0, false
	}
	switch {
	case identifier.Algorithm.Equal(oidMLDSA44):
		return x509.MLDSA44, true
	case identifier.Algorithm.Equal(oidMLDSA65):
		return x509.MLDSA65, true
	case identifier.Algorithm.Equal(oidMLDSA87):
		return x509.MLDSA87, true
	default:
		return 0, false
	}
}
