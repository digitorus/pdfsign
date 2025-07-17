package verify

import (
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/pdf"
)

// parseDocumentInfo parses document information from PDF Info dictionary.
func parseDocumentInfo(v pdf.Value, documentInfo *DocumentInfo) {
	keys := []string{
		"Author", "CreationDate", "Creator", "Hash", "Keywords", "ModDate",
		"Name", "Pages", "Permission", "Producer", "Subject", "Title",
	}

	for _, key := range keys {
		value := v.Key(key)
		if !value.IsNull() {
			// get string value
			valueStr := value.Text()

			// get struct field
			elem := reflect.ValueOf(documentInfo).Elem()
			field := elem.FieldByName(key)

			switch key {
			// parse dates
			case "CreationDate", "ModDate":
				t, _ := parseDate(valueStr)
				field.Set(reflect.ValueOf(t))
			// parse pages
			case "Pages":
				i, _ := strconv.Atoi(valueStr)
				documentInfo.Pages = i
			case "Keywords":
				documentInfo.Keywords = parseKeywords(valueStr)
			default:
				field.Set(reflect.ValueOf(valueStr))
			}
		}
	}
}

// parseDate parses PDF formatted dates.
func parseDate(v string) (time.Time, error) {
	// PDF Date Format
	// (D:YYYYMMDDHHmmSSOHH'mm')
	//
	// where
	//
	// YYYY is the year
	// MM is the month
	// DD is the day (01-31)
	// HH is the hour (00-23)
	// mm is the minute (00-59)
	// SS is the second (00-59)
	// O is the relationship of local time to Universal Time (UT), denoted by one of the characters +, -, or Z (see below)
	// HH followed by ' is the absolute value of the offset from UT in hours (00-23)
	// mm followed by ' is the absolute value of the offset from UT in minutes (00-59)

	// 2006-01-02T15:04:05Z07:00
	// (D:YYYYMMDDHHmmSSOHH'mm')
	return time.Parse("D:20060102150405Z07'00'", v)
}

// parseKeywords parses keywords PDF metadata.
func parseKeywords(value string) []string {
	// keywords must be separated by commas or semicolons or could be just separated with spaces, after the semicolon could be a space
	// https://stackoverflow.com/questions/44608608/the-separator-between-keywords-in-pdf-meta-data
	separators := []string{", ", ": ", ",", ":", " ", "; ", ";", " ;"}
	for _, s := range separators {
		if strings.Contains(value, s) {
			return strings.Split(value, s)
		}
	}

	return []string{value}
}
