module github.com/digitorus/pdfsign/signers/csc

go 1.26.0

replace github.com/digitorus/pdfsign => ../../

require github.com/digitorus/pdfsign v0.0.0-00010101000000-000000000000

require (
	github.com/digitorus/pkcs7 v0.0.0-20250730155240-ffadbf3f398c // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	golang.org/x/crypto v0.54.0 // indirect
)
