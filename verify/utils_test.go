package verify

import (
	"testing"
	"time"
)

func TestParseDate(t *testing.T) {
	tests := []struct {
		input    string
		expected bool // whether parsing should succeed
		name     string
	}{
		{
			input:    "D:20240101120000+01'00'",
			expected: true,
			name:     "date with positive timezone offset",
		},
		{
			input:    "D:20240101120000-05'00'",
			expected: true,
			name:     "date with negative timezone offset",
		},
		{
			input:    "invalid date",
			expected: false,
			name:     "invalid date format",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := parseDate(test.input)
			
			if test.expected {
				if err != nil {
					t.Errorf("Expected parsing to succeed, but got error: %v", err)
				} else {
					t.Logf("Parsed date: %s -> %s", test.input, result.Format(time.RFC3339))
				}
			} else {
				if err == nil {
					t.Errorf("Expected parsing to fail, but got result: %s", result.Format(time.RFC3339))
				} else {
					t.Logf("Expected error for invalid input: %v", err)
				}
			}
		})
	}
}

func TestParseKeywords(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
		name     string
	}{
		{
			input:    "keyword1, keyword2, keyword3",
			expected: []string{"keyword1", "keyword2", "keyword3"},
			name:     "comma and space separated",
		},
		{
			input:    "keyword1,keyword2,keyword3",
			expected: []string{"keyword1", "keyword2", "keyword3"},
			name:     "comma separated",
		},
		{
			input:    "keyword1: keyword2: keyword3",
			expected: []string{"keyword1", "keyword2", "keyword3"},
			name:     "colon and space separated",
		},
		{
			input:    "keyword1:keyword2:keyword3",
			expected: []string{"keyword1", "keyword2", "keyword3"},
			name:     "colon separated",
		},
		{
			input:    "keyword1 keyword2 keyword3",
			expected: []string{"keyword1", "keyword2", "keyword3"},
			name:     "space separated",
		},
		{
			input:    "single_keyword",
			expected: []string{"single_keyword"},
			name:     "single keyword",
		},
		{
			input:    "",
			expected: []string{""},
			name:     "empty string",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := parseKeywords(test.input)
			
			if len(result) != len(test.expected) {
				t.Errorf("Expected %d keywords, got %d", len(test.expected), len(result))
				return
			}
			
			for i, keyword := range result {
				if keyword != test.expected[i] {
					t.Errorf("Expected keyword %d to be %q, got %q", i, test.expected[i], keyword)
				}
			}
			
			t.Logf("Input: %q -> %v", test.input, result)
		})
	}
}
