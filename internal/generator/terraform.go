package generator

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]`)

// TerraformGenerator produces review-only Terraform HCL output.
type TerraformGenerator struct{}

// Generate writes one review-only local value containing all analyzed IAM roles.
func (g *TerraformGenerator) Generate(results []correlation.Result, w io.Writer) error {
	write := func(format string, args ...any) error {
		output := fmt.Sprintf(format, args...)
		written, err := io.WriteString(w, output)
		if err != nil {
			return err
		}
		if written != len(output) {
			return io.ErrShortWrite
		}
		return nil
	}
	writeStrings := func(name string, values []string) error {
		if err := write("      %s = [\n", name); err != nil {
			return err
		}
		for _, value := range values {
			if err := write("        %s,\n", hclQuote(value)); err != nil {
				return err
			}
		}
		return write("      ]\n")
	}

	if err := write("# SHINKAI-SHOUJO REVIEW OUTPUT ONLY\n"); err != nil {
		return err
	}
	if err := write("# This file does not modify IAM and contains no deployable resources.\n"); err != nil {
		return err
	}
	if err := write("# Candidate-unused permissions require human review before any IAM change.\n\n"); err != nil {
		return err
	}
	if len(results) == 0 {
		return write("locals {\n  shinkai_shoujo_review = []\n}\n")
	}
	if err := write("locals {\n  shinkai_shoujo_review = [\n"); err != nil {
		return err
	}

	for _, result := range results {
		if err := write("    {\n"); err != nil {
			return err
		}
		fields := []struct {
			name  string
			value string
		}{
			{name: "account_id", value: result.AccountID},
			{name: "iam_role", value: result.IAMRole},
			{name: "risk_level", value: result.RiskLevel},
			{name: "observation_start", value: formatHCLTime(result.ObservationStart)},
			{name: "analyzed_at", value: formatHCLTime(result.AnalyzedAt)},
		}
		for _, field := range fields {
			if err := write("      %s = %s\n", field.name, hclQuote(field.value)); err != nil {
				return err
			}
		}
		for _, list := range []struct {
			name   string
			values []string
		}{
			{name: "used", values: result.Used},
			{name: "candidate_unused", values: result.Unused},
			{name: "unresolved", values: result.Unresolved},
			{name: "warnings", values: result.Warnings},
		} {
			if err := writeStrings(list.name, list.values); err != nil {
				return err
			}
		}
		if err := write("      usage = [\n"); err != nil {
			return err
		}
		for _, usage := range result.Usage {
			if err := write("        {\n"); err != nil {
				return err
			}
			if err := write("          action = %s\n", hclQuote(usage.Action)); err != nil {
				return err
			}
			if err := write("          successful_events = %d\n", usage.SuccessfulEvents); err != nil {
				return err
			}
			if err := write("          denied_events = %d\n", usage.DeniedEvents); err != nil {
				return err
			}
			if err := write("          failed_events = %d\n", usage.FailedEvents); err != nil {
				return err
			}
			if err := write("          first_success = %s\n", hclQuote(formatHCLTime(usage.FirstSuccess))); err != nil {
				return err
			}
			if err := write("          last_success = %s\n", hclQuote(formatHCLTime(usage.LastSuccess))); err != nil {
				return err
			}
			if err := write("        },\n"); err != nil {
				return err
			}
		}
		if err := write("      ]\n    },\n"); err != nil {
			return err
		}
	}

	return write("  ]\n}\n")
}

func formatHCLTime(value time.Time) string {
	return value.Format(time.RFC3339Nano)
}

// hclQuote emits a quoted HCL template string without allowing interpolation.
func hclQuote(value string) string {
	const hex = "0123456789abcdef"

	var quoted strings.Builder
	quoted.Grow(len(value) + 2)
	quoted.WriteByte('"')
	for len(value) > 0 {
		if len(value) >= 2 && value[1] == '{' {
			switch value[0] {
			case '$':
				quoted.WriteString("$${")
				value = value[2:]
				continue
			case '%':
				quoted.WriteString("%%{")
				value = value[2:]
				continue
			}
		}

		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		switch r {
		case '"', '\\':
			quoted.WriteByte('\\')
			quoted.WriteRune(r)
		case '\n':
			quoted.WriteString(`\n`)
		case '\r':
			quoted.WriteString(`\r`)
		case '\t':
			quoted.WriteString(`\t`)
		case utf8.RuneError:
			quoted.WriteRune(utf8.RuneError)
		default:
			if r < 0x20 {
				quoted.WriteString(`\u00`)
				quoted.WriteByte(hex[byte(r)>>4])
				quoted.WriteByte(hex[byte(r)&0x0f])
			} else if r == '\u2028' || r == '\u2029' {
				quoted.WriteString(`\u202`)
				quoted.WriteByte(hex[byte(r)&0x0f])
			} else {
				quoted.WriteRune(r)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

// terraformResourceName converts an IAM role ARN or name to a valid Terraform resource name.
func terraformResourceName(roleARN string) string {
	lower := strings.ToLower(roleARN)
	safe := nonAlnum.ReplaceAllString(lower, "_")
	safe = strings.Trim(safe, "_")
	if safe == "" {
		safe = "role"
	}
	return safe
}
