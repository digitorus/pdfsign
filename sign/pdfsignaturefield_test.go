package sign_test

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/internal/acroform"
	"github.com/digitorus/pdfsign/sign"
)

// signatureFieldsFile holds three unsigned fields on page 1: the merged
// field and widget "Signature1", the signature field "parent.child", whose
// type is inherited from "parent" and whose widget is a separate kid, and
// the text field "Text1".
const signatureFieldsFile = "../testfiles/testfile_signature_fields.pdf"

func existingFieldSignData(t *testing.T, fieldName string) sign.SignData {
	t.Helper()

	cert, pkey := sign.LoadCertificateAndKey(t)
	if cert == nil || pkey == nil {
		t.FailNow()
	}

	return sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name: "John Doe",
				Date: time.Now().Local(),
			},
			CertType: sign.ApprovalSignature,
		},
		DigestAlgorithm: crypto.SHA256,
		Signer:          pkey,
		Certificate:     cert,
		SubFilter:       sign.SubFilterETSICAdESDetached,
		FieldName:       fieldName,
	}
}

func signExistingField(t *testing.T, inputFilePath, fieldName string) string {
	t.Helper()

	outputFilePath := filepath.Join(t.TempDir(), strings.ReplaceAll(fieldName, ".", "_")+".pdf")
	if err := sign.SignFile(inputFilePath, outputFilePath, existingFieldSignData(t, fieldName)); err != nil {
		t.Fatalf("failed to sign field %q: %v", fieldName, err)
	}

	return outputFilePath
}

// signatureFieldValues maps the fully qualified name of every signature field
// in the file to whether it holds a signature.
func signatureFieldValues(t *testing.T, filePath string) map[string]bool {
	t.Helper()

	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	rdr, err := pdf.NewReader(file, info.Size())
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	fields := make(map[string]bool)
	acroform.Fields(rdr.Trailer().Key("Root"), func(f acroform.Field) bool {
		if f.Type == "Sig" && f.Terminal {
			fields[f.Name] = !f.Value.IsNull()
		}
		return true
	})

	return fields
}

func assertSignatureFields(t *testing.T, filePath string, want map[string]bool) {
	t.Helper()

	got := signatureFieldValues(t, filePath)
	if len(got) != len(want) {
		t.Fatalf("signature fields = %v, want %v", got, want)
	}
	for name, signed := range want {
		if gotSigned, ok := got[name]; !ok || gotSigned != signed {
			t.Fatalf("signature fields = %v, want %v", got, want)
		}
	}
}

func verifyFile(t *testing.T, filePath string) {
	t.Helper()

	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	defer func() { _ = file.Close() }()

	verifySignedFile(t, file, filepath.Base(filePath))
}

func TestSignExistingField(t *testing.T) {
	for _, tc := range []struct {
		name      string
		fieldName string
		want      map[string]bool
	}{
		{
			name:      "merged field and widget",
			fieldName: "Signature1",
			want:      map[string]bool{"Signature1": true, "parent.child": false},
		},
		{
			name:      "nested field with a separate widget",
			fieldName: "parent.child",
			want:      map[string]bool{"Signature1": false, "parent.child": true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outputFilePath := signExistingField(t, signatureFieldsFile, tc.fieldName)

			assertSignatureFields(t, outputFilePath, tc.want)
			verifyFile(t, outputFilePath)
		})
	}
}

func TestSignExistingFieldKeepsPreviousRevision(t *testing.T) {
	original, err := os.ReadFile(signatureFieldsFile)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	outputFilePath := signExistingField(t, signatureFieldsFile, "Signature1")

	signed, err := os.ReadFile(outputFilePath)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	if !bytes.HasPrefix(signed, original) {
		t.Fatal("signing an existing field changed the bytes of the previous revision")
	}
}

func TestSignExistingFieldsOneAfterAnother(t *testing.T) {
	first := signExistingField(t, signatureFieldsFile, "Signature1")
	second := signExistingField(t, first, "parent.child")

	assertSignatureFields(t, second, map[string]bool{"Signature1": true, "parent.child": true})
	verifyFile(t, second)
}

func TestSignExistingFieldRejectsField(t *testing.T) {
	signed := signExistingField(t, signatureFieldsFile, "Signature1")

	for _, tc := range []struct {
		name          string
		inputFilePath string
		fieldName     string
		visible       bool
		wantErr       string
	}{
		{
			name:          "missing field",
			inputFilePath: signatureFieldsFile,
			fieldName:     "Missing",
			wantErr:       `signature field "Missing" not found`,
		},
		{
			name:          "text field",
			inputFilePath: signatureFieldsFile,
			fieldName:     "Text1",
			wantErr:       `field "Text1" is not a signature field (/FT /Tx)`,
		},
		{
			name:          "non-terminal field",
			inputFilePath: signatureFieldsFile,
			fieldName:     "parent",
			wantErr:       `signature field "parent" has child fields`,
		},
		{
			name:          "already signed field",
			inputFilePath: signed,
			fieldName:     "Signature1",
			wantErr:       `signature field "Signature1" is already signed`,
		},
		{
			name:          "visible appearance",
			inputFilePath: signatureFieldsFile,
			fieldName:     "Signature1",
			visible:       true,
			wantErr:       "a visible appearance cannot be set when signing an existing field",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signData := existingFieldSignData(t, tc.fieldName)
			signData.Appearance = sign.Appearance{
				Visible:     tc.visible,
				Page:        1,
				UpperRightX: 100,
				UpperRightY: 50,
			}

			outputFilePath := filepath.Join(t.TempDir(), "out.pdf")
			err := sign.SignFile(tc.inputFilePath, outputFilePath, signData)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
