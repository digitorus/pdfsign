// Package testdss provides test-only integration with the EU Digital
// Signature Services (DSS) validation API.
package testdss

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultHTTPTimeout = 30 * time.Second
	maxResponseSize    = 16 << 20
	maxErrorBodySize   = 64 << 10
)

// Client submits signed documents to a DSS validation endpoint.
type Client struct {
	endpoint   string
	httpClient *http.Client
}

// New creates a DSS validation client with a bounded HTTP timeout.
func New(endpoint string) *Client {
	return &Client{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}
}

// Response contains the DSS validation reports used by the integration tests.
type Response struct {
	SimpleReport   SimpleReport   `json:"simpleReport"`
	DetailedReport map[string]any `json:"detailedReport"`
	DiagnosticData map[string]any `json:"diagnosticData"`
}

// SimpleReport contains the summary returned by DSS.
type SimpleReport struct {
	Valid                bool          `json:"valid"`
	SignaturesCount      int           `json:"signaturesCount"`
	ValidSignaturesCount int           `json:"validSignaturesCount"`
	Entries              []ReportEntry `json:"signatureOrTimestampOrEvidenceRecord"`
}

// ReportEntry represents one signature, timestamp, or evidence-record entry.
// Signature is nil for entries that do not describe a signature.
type ReportEntry struct {
	Signature *Signature `json:"signature"`
}

// Signature contains the fields asserted by the repository's DSS tests.
type Signature struct {
	SignatureFormat string `json:"signatureFormat"`
	Indication      string `json:"indication"`
	SubIndication   string `json:"subIndication"`
}

type validationRequest struct {
	SignedDocument document `json:"signedDocument"`
}

type document struct {
	Bytes string `json:"bytes"`
	Name  string `json:"name"`
}

// Signatures returns only the signature entries from the mixed DSS report.
func (r Response) Signatures() []Signature {
	signatures := make([]Signature, 0, len(r.SimpleReport.Entries))
	for _, entry := range r.SimpleReport.Entries {
		if entry.Signature != nil {
			signatures = append(signatures, *entry.Signature)
		}
	}
	return signatures
}

// Validate submits documentBytes to DSS and returns its validation report.
// A response that reports no signatures, or reports signatures without any
// decodable signature entries, is rejected so schema drift cannot silently
// turn the integration test into a false positive.
func (c *Client) Validate(ctx context.Context, name string, documentBytes []byte) (Response, error) {
	var result Response

	if ctx == nil {
		return result, fmt.Errorf("DSS validation context must not be nil")
	}
	if strings.TrimSpace(c.endpoint) == "" {
		return result, fmt.Errorf("DSS validation endpoint must not be empty")
	}
	if strings.TrimSpace(name) == "" {
		return result, fmt.Errorf("DSS document name must not be empty")
	}
	if len(documentBytes) == 0 {
		return result, fmt.Errorf("DSS document must not be empty")
	}

	payload, err := json.Marshal(validationRequest{
		SignedDocument: document{
			Bytes: base64.StdEncoding.EncodeToString(documentBytes),
			Name:  name,
		},
	})
	if err != nil {
		return result, fmt.Errorf("encode DSS validation request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return result, fmt.Errorf("create DSS validation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("call DSS validation API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return result, fmt.Errorf("read DSS validation response: %w", err)
	}
	if len(body) > maxResponseSize {
		return result, fmt.Errorf("DSS validation response exceeds %d bytes", maxResponseSize)
	}
	if resp.StatusCode != http.StatusOK {
		if len(body) > maxErrorBodySize {
			body = body[:maxErrorBodySize]
		}
		return result, fmt.Errorf("DSS validation API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return Response{}, fmt.Errorf("decode DSS validation response: %w", err)
	}
	if result.SimpleReport.SignaturesCount < 1 {
		return Response{}, fmt.Errorf("DSS validation response reports no signatures")
	}
	if len(result.Signatures()) == 0 {
		return Response{}, fmt.Errorf("DSS validation response contains no signature entries")
	}

	return result, nil
}
