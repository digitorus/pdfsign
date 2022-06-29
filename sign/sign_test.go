package sign

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitorus/pdf"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/verify"

	"github.com/mattetti/filebuffer"
)

const signCertPem = `-----BEGIN CERTIFICATE-----
MIIDBzCCAnCgAwIBAgIJAIJ/XyRx/DG0MA0GCSqGSIb3DQEBCwUAMIGZMQswCQYD
VQQGEwJOTDEVMBMGA1UECAwMWnVpZC1Ib2xsYW5kMRIwEAYDVQQHDAlSb3R0ZXJk
YW0xEjAQBgNVBAoMCVVuaWNvZGVyczELMAkGA1UECwwCSVQxGjAYBgNVBAMMEUpl
cm9lbiBCb2JiZWxkaWprMSIwIAYJKoZIhvcNAQkBFhNqZXJvZW5AdW5pY29kZXJz
Lm5sMCAXDTE3MDkxNzExMjkzNloYDzMwMTcwMTE4MTEyOTM2WjCBmTELMAkGA1UE
BhMCTkwxFTATBgNVBAgMDFp1aWQtSG9sbGFuZDESMBAGA1UEBwwJUm90dGVyZGFt
MRIwEAYDVQQKDAlVbmljb2RlcnMxCzAJBgNVBAsMAklUMRowGAYDVQQDDBFKZXJv
ZW4gQm9iYmVsZGlqazEiMCAGCSqGSIb3DQEJARYTamVyb2VuQHVuaWNvZGVycy5u
bDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmrvrZiUZZ/nSmFKMsQXg5slY
TQjj7nuenczt7KGPVuGA8nNOqiGktf+yep5h2r87jPvVjVXjJVjOTKx9HMhaFECH
KHKV72iQhlw4fXa8iB1EDeGuwP+pTpRWlzurQ/YMxvemNJVcGMfTE42X5Bgqh6Dv
kddRTAeeqQDBD6+5VPsCAwEAAaNTMFEwHQYDVR0OBBYEFETizi2bTLRMIknQXWDR
nQ59xI99MB8GA1UdIwQYMBaAFETizi2bTLRMIknQXWDRnQ59xI99MA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOHdI9f4I1rd7DjOXnT6IJl/4mIQ
kkaeZkjcsgdZAeW154vjDEr8sIdq+W15huWJKZkqwhn1sJLqSOlEhaYbJJNHVKc9
ZH5r6ujfc336AtjrjCL3OYHQQj05isKm9ii5IL/i+rlZ5xro/dJ91jnjqNVQPvso
oA4h5BVsLZPIYto=
-----END CERTIFICATE-----`

const signKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCau+tmJRln+dKYUoyxBeDmyVhNCOPue56dzO3soY9W4YDyc06q
IaS1/7J6nmHavzuM+9WNVeMlWM5MrH0cyFoUQIcocpXvaJCGXDh9dryIHUQN4a7A
/6lOlFaXO6tD9gzG96Y0lVwYx9MTjZfkGCqHoO+R11FMB56pAMEPr7lU+wIDAQAB
AoGADPlKsILV0YEB5mGtiD488DzbmYHwUpOs5gBDxr55HUjFHg8K/nrZq6Tn2x4i
iEvWe2i2LCaSaBQ9H/KqftpRqxWld2/uLbdml7kbPh0+57/jsuZZs3jlN76HPMTr
uYcfG2UiU/wVTcWjQLURDotdI6HLH2Y9MeJhybctywDKWaECQQDNejmEUybbg0qW
2KT5u9OykUpRSlV3yoGlEuL2VXl1w5dUMa3rw0yE4f7ouWCthWoiCn7dcPIaZeFf
5CoshsKrAkEAwMenQppKsLk62m8F4365mPxV/Lo+ODg4JR7uuy3kFcGvRyGML/FS
TB5NI+DoTmGEOZVmZeLEoeeSnO0B52Q28QJAXFJcYW4S+XImI1y301VnKsZJA/lI
KYidc5Pm0hNZfWYiKjwgDtwzF0mLhPk1zQEyzJS2p7xFq0K3XqRfpp3t/QJACW77
sVephgJabev25s4BuQnID2jxuICPxsk/t2skeSgUMq/ik0oE0/K7paDQ3V0KQmMc
MqopIx8Y3pL+f9s4kQJADWxxuF+Rb7FliXL761oa2rZHo4eciey2rPhJIU/9jpCc
xLqE5nXC5oIUTbuSK+b/poFFrtjKUFgxf0a/W2Ktsw==
-----END RSA PRIVATE KEY-----`

const staticPDFFile = `JVBERi0yLjANCg0KMSAwIG9iag0KPDwNCiAgL1R5cGUgL0NhdGFsb2cNCiAgL01ldGFkYXRhIDIgMCBSDQogIC9QYWdlcyAzIDAgUg0KPj4NCmVuZG9iag0KDQoyIDAgb2JqDQo8PA0KICAvTGVuZ3RoIDIzNTENCiAgL1R5cGUgL01ldGFkYXRhDQogIC9TdWJ0eXBlIC9YTUwNCj4+DQpzdHJlYW0NCjx4OnhtcG1ldGEgeG1sbnM6eD0nYWRvYmU6bnM6bWV0YS8nIHg6eG1wdGs9J0luc2VydCBYTVAgdG9vbCBuYW1lIGhlcmUuJz4NCiAgPHJkZjpSREYgeG1sbnM6cmRmPSdodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjJz4NCiAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczpwZGY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vcGRmLzEuMy8iPg0KICAgICAgPHBkZjpQcm9kdWNlcj5EYXRhbG9naWNzIC0gZXhhbXBsZSBwcm9kdWNlciBwcm9ncmFtIG5hbWUgaGVyZTwvcGRmOlByb2R1Y2VyPg0KICAgICAgPHBkZjpDb3B5cmlnaHQ+Q29weXJpZ2h0IDIwMTcgUERGIEFzc29jaWF0aW9uPC9wZGY6Q29weXJpZ2h0Pg0KICAgICAgPHBkZjpLZXl3b3Jkcz5QREYgMi4wIHNhbXBsZSBleGFtcGxlPC9wZGY6S2V5d29yZHM+DQogICAgPC9yZGY6RGVzY3JpcHRpb24+DQogICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eGFwPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIj4NCiAgICAgIDx4YXA6Q3JlYXRlRGF0ZT4yMDE3LTA1LTI0VDEwOjMwOjExWjwveGFwOkNyZWF0ZURhdGU+DQogICAgICA8eGFwOk1ldGFkYXRhRGF0ZT4yMDE3LTA3LTExVDA3OjU1OjExWjwveGFwOk1ldGFkYXRhRGF0ZT4NCiAgICAgIDx4YXA6TW9kaWZ5RGF0ZT4yMDE3LTA3LTExVDA3OjU1OjExWjwveGFwOk1vZGlmeURhdGU+DQogICAgICA8eGFwOkNyZWF0b3JUb29sPkRhdGFsb2dpY3MgLSBleGFtcGxlIGNyZWF0b3IgdG9vbCBuYW1lIGhlcmU8L3hhcDpDcmVhdG9yVG9vbD4NCiAgICA8L3JkZjpEZXNjcmlwdGlvbj4NCiAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iPg0KICAgICAgPGRjOmZvcm1hdD5hcHBsaWNhdGlvbi9wZGY8L2RjOmZvcm1hdD4NCiAgICAgIDxkYzp0aXRsZT4NCiAgICAgICAgPHJkZjpBbHQ+DQogICAgICAgICAgPHJkZjpsaSB4bWw6bGFuZz0ieC1kZWZhdWx0Ij5BIHNpbXBsZSBQREYgMi4wIGV4YW1wbGUgZmlsZTwvcmRmOmxpPg0KICAgICAgICA8L3JkZjpBbHQ+DQogICAgICA8L2RjOnRpdGxlPg0KICAgICAgPGRjOmNyZWF0b3I+DQogICAgICAgIDxyZGY6U2VxPg0KICAgICAgICAgIDxyZGY6bGk+RGF0YWxvZ2ljcyBJbmNvcnBvcmF0ZWQ8L3JkZjpsaT4NCiAgICAgICAgPC9yZGY6U2VxPg0KICAgICAgPC9kYzpjcmVhdG9yPg0KICAgICAgPGRjOmRlc2NyaXB0aW9uPg0KICAgICAgICA8cmRmOkFsdD4NCiAgICAgICAgICA8cmRmOmxpIHhtbDpsYW5nPSJ4LWRlZmF1bHQiPkRlbW9uc3RyYXRpb24gb2YgYSBzaW1wbGUgUERGIDIuMCBmaWxlLjwvcmRmOmxpPg0KICAgICAgICA8L3JkZjpBbHQ+DQogICAgICA8L2RjOmRlc2NyaXB0aW9uPg0KICAgICAgPGRjOnJpZ2h0cz4NCiAgICAgICAgPHJkZjpBbHQ+DQogICAgICAgICAgPHJkZjpsaSB4bWw6bGFuZz0ieC1kZWZhdWx0Ij5Db3B5cmlnaHQgMjAxNyBQREYgQXNzb2NpYXRpb24uIExpY2Vuc2VkIHRvIHRoZSBwdWJsaWMgdW5kZXIgQ3JlYXRpdmUgQ29tbW9ucyBBdHRyaWJ1dGlvbi1TaGFyZUFsaWtlIDQuMCBJbnRlcm5hdGlvbmFsIGxpY2Vuc2UuPC9yZGY6bGk+DQogICAgICAgIDwvcmRmOkFsdD4NCiAgICAgIDwvZGM6cmlnaHRzPg0KICAgIDwvcmRmOkRlc2NyaXB0aW9uPg0KICAgIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiIHhtbG5zOnhhcFJpZ2h0cz0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3JpZ2h0cy8iPg0KICAgICAgPHhhcFJpZ2h0czpNYXJrZWQ+VHJ1ZTwveGFwUmlnaHRzOk1hcmtlZD4NCiAgICA8L3JkZjpEZXNjcmlwdGlvbj4NCiAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczpjYz0iaHR0cDovL2NyZWF0aXZlY29tbW9ucy5vcmcvbnMjIj4NCiAgICAgIDxjYzpsaWNlbnNlIHJkZjpyZXNvdXJjZT0iaHR0cHM6Ly9jcmVhdGl2ZWNvbW1vbnMub3JnL2xpY2Vuc2VzL3NhLzQuMC8iIC8+DQogICAgPC9yZGY6RGVzY3JpcHRpb24+DQogICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eGFwTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iPg0KICAgICAgPHhhcE1NOkRvY3VtZW50SUQ+dXVpZDozZWVmMjE2Ni04MzMyLWFiYjQtM2QzMS03NzMzNDU3ODg3M2Y8L3hhcE1NOkRvY3VtZW50SUQ+DQogICAgICA8eGFwTU06SW5zdGFuY2VJRD51dWlkOjk5MWJjY2U3LWVlNzAtMTFhMy05MWFhLTc3YmJlMjE4MWZkODwveGFwTU06SW5zdGFuY2VJRD4NCiAgICA8L3JkZjpEZXNjcmlwdGlvbj4NCiAgPC9yZGY6UkRGPg0KPC94OnhtcG1ldGE+DQplbmRzdHJlYW0NCmVuZG9iag0KDQozIDAgb2JqDQo8PA0KICAvVHlwZSAvUGFnZXMNCiAgL0tpZHMgWzQgMCBSXQ0KICAvQ291bnQgMQ0KPj4NCmVuZG9iag0KDQo0IDAgb2JqDQo8PA0KICAvVHlwZSAvUGFnZQ0KICAvUGFyZW50IDMgMCBSDQogIC9NZWRpYUJveCBbMCAwIDYxMiAzOTZdDQogIC9Db250ZW50cyBbNSAwIFIgNiAwIFJdDQogIC9SZXNvdXJjZXMgPDwNCiAgICAvRm9udCA8PCAvRjEgNyAwIFIgPj4NCiAgPj4NCj4+DQplbmRvYmoNCg0KNSAwIG9iag0KPDwgL0xlbmd0aCA3NDQgPj4NCnN0cmVhbQ0KJSBTYXZlIHRoZSBjdXJyZW50IGdyYXBoaWMgc3RhdGUNCnEgDQoNCiUgRHJhdyBhIGJsYWNrIGxpbmUgc2VnbWVudCwgdXNpbmcgdGhlIGRlZmF1bHQgbGluZSB3aWR0aC4NCjE1MCAyNTAgbQ0KMTUwIDM1MCBsDQpTDQoNCiUgRHJhdyBhIHRoaWNrZXIsIGRhc2hlZCBsaW5lIHNlZ21lbnQuDQo0IHcgJSBTZXQgbGluZSB3aWR0aCB0byA0IHBvaW50cw0KWzQgNl0gMCBkICUgU2V0IGRhc2ggcGF0dGVybiB0byA0IHVuaXRzIG9uLCA2IHVuaXRzIG9mZg0KMTUwIDI1MCBtDQo0MDAgMjUwIGwNClMNCltdIDAgZCAlIFJlc2V0IGRhc2ggcGF0dGVybiB0byBhIHNvbGlkIGxpbmUNCjEgdyAlIFJlc2V0IGxpbmUgd2lkdGggdG8gMSB1bml0DQoNCiUgRHJhdyBhIHJlY3RhbmdsZSB3aXRoIGEgMS11bml0IHJlZCBib3JkZXIsIGZpbGxlZCB3aXRoIGxpZ2h0IGJsdWUuDQoxLjAgMC4wIDAuMCBSRyAlIFJlZCBmb3Igc3Ryb2tlIGNvbG9yDQowLjUgMC43NSAxLjAgcmcgJSBMaWdodCBibHVlIGZvciBmaWxsIGNvbG9yDQoyMDAgMzAwIDUwIDc1IHJlDQpCDQoNCiUgRHJhdyBhIGN1cnZlIGZpbGxlZCB3aXRoIGdyYXkgYW5kIHdpdGggYSBjb2xvcmVkIGJvcmRlci4NCjAuNSAwLjEgMC4yIFJHDQowLjcgZw0KMzAwIDMwMCBtDQozMDAgNDAwIDQwMCA0MDAgNDAwIDMwMCBjDQpiDQoNCiUgUmVzdG9yZSB0aGUgZ3JhcGhpYyBzdGF0ZSB0byB3aGF0IGl0IHdhcyBhdCB0aGUgYmVnaW5uaW5nIG9mIHRoaXMgc3RyZWFtDQpRDQoNCmVuZHN0cmVhbQ0KZW5kb2JqDQoNCjYgMCBvYmoNCjw8IC9MZW5ndGggMTY2ID4+DQpzdHJlYW0NCiUgQSB0ZXh0IGJsb2NrIHRoYXQgc2hvd3MgIkhlbGxvIFdvcmxkIg0KJSBObyBjb2xvciBpcyBzZXQsIHNvIHRoaXMgZGVmYXVsdHMgdG8gYmxhY2sgaW4gRGV2aWNlR3JheSBjb2xvcnNwYWNlDQpCVA0KICAvRjEgMjQgVGYNCiAgMTAwIDEwMCBUZA0KICAoSGVsbG8gV29ybGQpIFRqDQpFVA0KZW5kc3RyZWFtDQplbmRvYmoNCg0KNyAwIG9iag0KPDwNCiAgL1R5cGUgL0ZvbnQNCiAgL1N1YnR5cGUgL1R5cGUxDQogIC9CYXNlRm9udCAvSGVsdmV0aWNhDQogIC9GaXJzdENoYXIgMzMNCiAgL0xhc3RDaGFyIDEyNg0KICAvV2lkdGhzIDggMCBSDQogIC9Gb250RGVzY3JpcHRvciA5IDAgUg0KPj4NCmVuZG9iag0KDQo4IDAgb2JqDQpbIDI3OCAzNTUgNTU2IDU1NiA4ODkgNjY3IDIyMiAzMzMgMzMzIDM4OSA1ODQgMjc4IDMzMyAyNzggMjc4IDU1Ng0KICA1NTYgNTU2IDU1NiA1NTYgNTU2IDU1NiA1NTYgNTU2IDU1NiAyNzggMjc4IDU4NCA1ODQgNTg0IDU1NiAxMDE1DQogIDY2NyA2NjcgNzIyIDcyMiA2NjcgNjExIDc3OCA3MjIgMjc4IDUwMCA2NjcgNTU2IDgzMyA3MjIgNzc4IDY2Nw0KICA3NzggNzIyIDY2NyA2MTEgNzIyIDY2NyA5NDQgNjY3IDY2NyA2MTEgMjc4IDI3OCAyNzggNDY5IDU1NiAyMjINCiAgNTU2IDU1NiA1MDAgNTU2IDU1NiAyNzggNTU2IDU1NiAyMjIgMjIyIDUwMCAyMjIgODMzIDU1NiA1NTYgNTU2DQogIDU1NiAzMzMgNTAwIDI3OCA1NTYgNTAwIDcyMiA1MDAgNTAwIDUwMCAzMzQgMjYwIDMzNCA1ODQgXQ0KZW5kb2JqDQoNCiUgVGhpcyBGb250RGVzY3JpcHRvciBjb250YWlucyBvbmx5IHRoZSByZXF1aXJlZCBlbnRyaWVzIGZvciBQREYgMi4wDQolIGZvciB1bmVtYmVkZGVkIHN0YW5kYXJkIDE0IGZvbnRzIHRoYXQgY29udGFpbiBMYXRpbiBjaGFyYWN0ZXJzDQo5IDAgb2JqDQo8PA0KICAvVHlwZSAvRm9udERlc2NyaXB0b3INCiAgL0ZvbnROYW1lIC9IZWx2ZXRpY2ENCiAgL0ZsYWdzIDMyDQogIC9Gb250QkJveCBbIC0xNjYgLTIyNSAxMDAwIDkzMSBdDQogIC9JdGFsaWNBbmdsZSAwDQogIC9Bc2NlbnQgNzE4DQogIC9EZXNjZW50IC0yMDcNCiAgL0NhcEhlaWdodCA3MTgNCiAgL1N0ZW1WIDg4DQogIC9NaXNzaW5nV2lkdGggMCAgDQo+Pg0KZW5kb2JqDQoNCiUgVGhlIG9iamVjdCBjcm9zcy1yZWZlcmVuY2UgdGFibGUuIFRoZSBmaXJzdCBlbnRyeQ0KJSBkZW5vdGVzIHRoZSBzdGFydCBvZiBQREYgZGF0YSBpbiB0aGlzIGZpbGUuDQp4cmVmDQowIDEwDQowMDAwMDAwMDAwIDY1NTM1IGYNCjAwMDAwMDAwMTIgMDAwMDAgbg0KMDAwMDAwMDA5MiAwMDAwMCBuDQowMDAwMDAyNTQzIDAwMDAwIG4NCjAwMDAwMDI2MTUgMDAwMDAgbg0KMDAwMDAwMjc3OCAwMDAwMCBuDQowMDAwMDAzNTgzIDAwMDAwIG4NCjAwMDAwMDM4MDcgMDAwMDAgbg0KMDAwMDAwMzk2OCAwMDAwMCBuDQowMDAwMDA0NTIwIDAwMDAwIG4NCnRyYWlsZXINCjw8DQogIC9TaXplIDEwDQogIC9Sb290IDEgMCBSDQogIC9JRCBbIDwzMWM3YThhMjY5ZTRjNTliYzNjZDdkZjBkYWJiZjM4OD48MzFjN2E4YTI2OWU0YzU5YmMzY2Q3ZGYwZGFiYmYzODg+IF0NCj4+DQpzdGFydHhyZWYNCjQ4NDcNCiUlRU9GDQo=`

func TestReaderCanReadPDF(t *testing.T) {
	files, err := ioutil.ReadDir("../testfiles")
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext != ".pdf" {
			t.Log("Skipping file", f.Name())
			continue
		}

		t.Run(f.Name(), func(st *testing.T) {
			st.Parallel()

			input_file, err := os.Open("../testfiles/" + f.Name())
			if err != nil {
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}

			finfo, err := input_file.Stat()
			if err != nil {
				input_file.Close()
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}
			size := finfo.Size()

			_, err = pdf.NewReader(input_file, size)
			if err != nil {
				input_file.Close()
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}

			input_file.Close()
		})

	}
}

func TestSignPDF(t *testing.T) {
	os.RemoveAll("../testfiles/failed/")
	os.MkdirAll("../testfiles/failed/", 0777)

	files, err := ioutil.ReadDir("../testfiles")
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		t.Errorf("failed to parse PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		t.Errorf("failed to parse PEM block containing the private key")
		return
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	certificate_chains := make([][]*x509.Certificate, 0)

	for _, f := range files {
		f := f

		ext := filepath.Ext(f.Name())
		if ext != ".pdf" {
			t.Log("Skipping file", f.Name())
			continue
		}

		t.Run(f.Name(), func(st *testing.T) {
			st.Parallel()

			t.Log("Signing file", f.Name())

			input_file, err := os.Open("../testfiles/" + f.Name())
			if err != nil {
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}

			finfo, err := input_file.Stat()
			if err != nil {
				input_file.Close()
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}
			size := finfo.Size()

			rdr, err := pdf.NewReader(input_file, size)
			if err != nil {
				input_file.Close()
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}

			outputFile, err := ioutil.TempFile("", "pdfsign_test")

			err = Sign(input_file, outputFile, rdr, size, SignData{
				Signature: SignDataSignature{
					Info: SignDataSignatureInfo{
						Name:        "John Doe",
						Location:    "Somewhere",
						Reason:      "Test",
						ContactInfo: "None",
						Date:        time.Now().Local(),
					},
					CertType:   CertificationSignature,
					DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
				},
				Signer:            pkey,
				Certificate:       cert,
				CertificateChains: certificate_chains,
				TSA: TSA{
					URL: "https://freetsa.org/tsr",
				},
				RevocationData:     revocation.InfoArchival{},
				RevocationFunction: DefaultEmbedRevocationStatusFunction,
			})

			if err != nil {
				input_file.Close()
				os.Remove(outputFile.Name())
				st.Errorf("%s: %s", f.Name(), err.Error())
				return
			}

			_, err = verify.File(outputFile)
			input_file.Close()
			if err != nil {
				err2 := os.Rename(outputFile.Name(), "../testfiles/failed/"+filepath.Base(input_file.Name()))
				if err2 != nil {
					st.Error(err2)
				}
				st.Errorf("%s: %s", f.Name(), err.Error())
			} else {
				os.Remove(outputFile.Name())
			}
		})
	}
}

func TestSignPDFFile(t *testing.T) {
	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		t.Errorf("failed to parse PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		t.Errorf("failed to parse PEM block containing the private key")
		return
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		t.Errorf("%s", err.Error())
		return
	}

	certificate_chains := make([][]*x509.Certificate, 0)

	tmpfile, err := ioutil.TempFile("", "pdfsign_test")

	err = SignFile("../testfiles/testfile20.pdf", tmpfile.Name(), SignData{
		Signature: SignDataSignature{
			Info: SignDataSignatureInfo{
				Name:        "John Doe",
				Location:    "Somewhere",
				Reason:      "Test",
				ContactInfo: "None",
				Date:        time.Now().Local(),
			},
			CertType:   CertificationSignature,
			DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            pkey,
		Certificate:       cert,
		CertificateChains: certificate_chains,
		RevocationData:    revocation.InfoArchival{},
	})

	if err != nil {
		os.Remove(tmpfile.Name())
		t.Errorf("%s: %s", "testfile20.pdf", err.Error())
		return
	}

	_, err = verify.File(tmpfile)
	os.Remove(tmpfile.Name())

	if err != nil {
		t.Errorf("%s: %s", tmpfile.Name(), err.Error())
	}

}

func BenchmarkSignPDF(b *testing.B) {
	certificate_data_block, _ := pem.Decode([]byte(signCertPem))
	if certificate_data_block == nil {
		b.Errorf("failed to parse PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(certificate_data_block.Bytes)
	if err != nil {
		b.Errorf("%s", err.Error())
		return
	}

	key_data_block, _ := pem.Decode([]byte(signKeyPem))
	if key_data_block == nil {
		b.Errorf("failed to parse PEM block containing the private key")
		return
	}

	pkey, err := x509.ParsePKCS1PrivateKey(key_data_block.Bytes)
	if err != nil {
		b.Errorf("%s", err.Error())
		return
	}

	certificate_chains := make([][]*x509.Certificate, 0)

	data, err := base64.StdEncoding.DecodeString(staticPDFFile)
	if err != nil {
		b.Errorf("%s: %s", "testfile20.pdf", err.Error())
		return
	}

	input_file := filebuffer.New(data)
	size := int64(len(data))

	rdr, err := pdf.NewReader(input_file, size)
	if err != nil {
		input_file.Close()
		b.Errorf("%s: %s", "testfile20.pdf", err.Error())
		return
	}

	for n := 0; n < b.N; n++ {
		input_file.Seek(0, 0)

		err = Sign(input_file, ioutil.Discard, rdr, size, SignData{
			Signature: SignDataSignature{
				Info: SignDataSignatureInfo{
					Name:        "John Doe",
					Location:    "Somewhere",
					Reason:      "Test",
					ContactInfo: "None",
					Date:        time.Now().Local(),
				},
				CertType:   CertificationSignature,
				DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
			},
			Signer:            pkey,
			Certificate:       cert,
			CertificateChains: certificate_chains,
			RevocationData:    revocation.InfoArchival{},
		})

		if err != nil {
			b.Errorf("%s: %s", "testfile20.pdf", err.Error())
			return
		}
	}

	input_file.Close()
}
