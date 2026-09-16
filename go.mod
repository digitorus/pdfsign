module github.com/digitorus/pdfsign

go 1.27.0

require (
	github.com/digitorus/pdf v0.2.0 // replaced below until digitorus/pdf#5 is released
	github.com/digitorus/pkcs7 v0.0.0-20260914070511-d678ea5ea03f
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea
	github.com/mattetti/filebuffer v1.0.1
	golang.org/x/crypto v0.57.0
	golang.org/x/image v0.46.0
	golang.org/x/text v0.42.0
)

// TODO(encrypted-documents): temporary. The API this branch needs
// (pdf.Reader.Encrypt/IsEncrypted/Trailer, pdf.Ptr) is digitorus/pdf#5, which is
// neither merged nor tagged, so it can only be reached through the fork the pull
// request was opened from. Once it is released, bump the require above and drop
// this line: a replace is ignored by consumers of this module.
replace github.com/digitorus/pdf => github.com/nascuite/pdf v0.0.0-20260917185623-d60316bf8156
