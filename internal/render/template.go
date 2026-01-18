package render

import (
	"regexp"
	"strings"
	"time"
)

var templateVarRegex = regexp.MustCompile(`\{\{(\w+)\}\}`)

// TemplateContext contains values for template variable substitution.
type TemplateContext struct {
	Name     string
	Date     time.Time
	Reason   string
	Location string
}

// ExpandTemplateVariables replaces template variables in text with values from context.
//
// Supported variables:
//   - {{Name}} - Signer name
//   - {{Date}} - Signing date (YYYY-MM-DD format)
//   - {{Reason}} - Signing reason
//   - {{Location}} - Signing location
//   - {{Initials}} - Initials derived from name
func ExpandTemplateVariables(text string, ctx TemplateContext) string {
	return templateVarRegex.ReplaceAllStringFunc(text, func(match string) string {
		varName := match[2 : len(match)-2] // Remove {{ and }}
		switch varName {
		case "Name":
			return ctx.Name
		case "Date":
			if ctx.Date.IsZero() {
				return time.Now().Format("2006-01-02")
			}
			return ctx.Date.Format("2006-01-02")
		case "Reason":
			return ctx.Reason
		case "Location":
			return ctx.Location
		case "Initials":
			return ExtractInitials(ctx.Name)
		default:
			return match // Keep unknown variables as-is
		}
	})
}

// ExtractInitials extracts initials from a name.
// "John Doe" -> "JD", "Alice Bob Charlie" -> "ABC"
func ExtractInitials(name string) string {
	if name == "" {
		return ""
	}

	parts := strings.Fields(name)
	var initials strings.Builder
	for _, part := range parts {
		if len(part) > 0 {
			for _, r := range part {
				initials.WriteRune(r)
				break
			}
		}
	}
	return strings.ToUpper(initials.String())
}
