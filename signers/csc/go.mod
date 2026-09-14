module github.com/digitorus/pdfsign/signers/csc

go 1.27.0

replace github.com/digitorus/pdfsign => ../../

require github.com/digitorus/pdfsign v0.0.0-00010101000000-000000000000

require (
	github.com/digitorus/pkcs7 v0.0.0-20260914070511-d678ea5ea03f // indirect
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea // indirect
	golang.org/x/crypto v0.56.0 // indirect
)
