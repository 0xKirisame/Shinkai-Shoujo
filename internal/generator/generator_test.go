package generator

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

var (
	observationStart = time.Date(2026, time.July, 1, 12, 0, 0, 0, time.UTC)
	analyzedAt       = time.Date(2026, time.August, 1, 12, 0, 0, 123, time.UTC)
	testResults      = []correlation.Result{
		{
			AccountID:        "123456789012",
			IAMRole:          "arn:aws:iam::123456789012:role/MyRole",
			Assigned:         []string{"s3:GetObject", "s3:PutObject", "ec2:*"},
			Used:             []string{"s3:GetObject"},
			Unused:           []string{"s3:PutObject"},
			Unresolved:       []string{"ec2:*"},
			Warnings:         []string{`review ${candidate} and %{directive}`},
			ObservationStart: observationStart,
			AnalyzedAt:       analyzedAt,
			RiskLevel:        "MEDIUM",
			Usage: []correlation.ActionUsage{
				{
					Action:           "s3:GetObject",
					SuccessfulEvents: 12,
					DeniedEvents:     2,
					FailedEvents:     1,
					FirstSuccess:     observationStart.Add(time.Hour),
					LastSuccess:      analyzedAt.Add(-time.Hour),
				},
			},
		},
		{
			AccountID:        "123456789012",
			IAMRole:          "arn:aws:iam::123456789012:role/ReadOnlyRole",
			ObservationStart: observationStart,
			AnalyzedAt:       analyzedAt,
			RiskLevel:        "LOW",
		},
	}
)

func TestJSONGenerator(t *testing.T) {
	var buf bytes.Buffer
	if err := (&JSONGenerator{}).Generate(testResults, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}
	if len(report.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(report.Roles))
	}

	role := report.Roles[0]
	if role.AccountID != testResults[0].AccountID || role.IAMRole != testResults[0].IAMRole {
		t.Errorf("role identity was not preserved: %+v", role)
	}
	if role.RiskLevel != "MEDIUM" || !role.ObservationStart.Equal(observationStart) || !role.AnalyzedAt.Equal(analyzedAt) {
		t.Errorf("role analysis metadata was not preserved: %+v", role)
	}
	if role.AssignedCount != 3 || role.UsedCount != 1 || role.CandidateUnusedCount != 1 || role.UnresolvedCount != 1 {
		t.Errorf("unexpected counts: %+v", role)
	}
	if len(role.Assigned) != 3 || len(role.Used) != 1 || len(role.CandidateUnused) != 1 || len(role.Unresolved) != 1 {
		t.Errorf("analysis arrays were not preserved: %+v", role)
	}
	if len(role.Warnings) != 1 || len(role.Usage) != 1 {
		t.Errorf("warnings or usage were not preserved: %+v", role)
	}
	usage := role.Usage[0]
	if usage.Action != "s3:GetObject" || usage.SuccessfulEvents != 12 || usage.DeniedEvents != 2 || usage.FailedEvents != 1 {
		t.Errorf("usage summary was not preserved: %+v", usage)
	}
	if !usage.FirstSuccess.Equal(testResults[0].Usage[0].FirstSuccess) || !usage.LastSuccess.Equal(testResults[0].Usage[0].LastSuccess) {
		t.Errorf("usage timestamps were not preserved: %+v", usage)
	}

	var raw struct {
		Roles []map[string]json.RawMessage `json:"roles"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to inspect JSON output: %v", err)
	}
	requiredFields := []string{
		"account_id", "iam_role", "risk_level", "observation_start", "analyzed_at",
		"assigned", "assigned_count", "used", "used_count", "candidate_unused",
		"candidate_unused_count", "unresolved", "unresolved_count", "warnings", "usage",
	}
	arrayFields := []string{"assigned", "used", "candidate_unused", "unresolved", "warnings", "usage"}
	for i, rawRole := range raw.Roles {
		for _, field := range requiredFields {
			if _, ok := rawRole[field]; !ok {
				t.Errorf("role %d is missing JSON field %q", i, field)
			}
		}
		for _, field := range arrayFields {
			if string(rawRole[field]) == "null" {
				t.Errorf("role %d field %q must not be null", i, field)
			}
		}
	}

	var usageEntries []map[string]json.RawMessage
	if err := json.Unmarshal(raw.Roles[0]["usage"], &usageEntries); err != nil {
		t.Fatalf("failed to inspect usage JSON: %v", err)
	}
	for _, field := range []string{"action", "successful_events", "denied_events", "failed_events", "first_success", "last_success"} {
		if _, ok := usageEntries[0][field]; !ok {
			t.Errorf("usage entry is missing JSON field %q", field)
		}
	}
}

func TestYAMLGenerator(t *testing.T) {
	var buf bytes.Buffer
	if err := (&YAMLGenerator{}).Generate(testResults, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	for _, field := range []string{
		"account_id:", "iam_role:", "risk_level:", "observation_start:", "analyzed_at:",
		"assigned:", "assigned_count:", "used:", "used_count:", "candidate_unused:",
		"candidate_unused_count:", "unresolved:", "unresolved_count:", "warnings:", "usage:",
		"successful_events:", "denied_events:", "failed_events:", "first_success:", "last_success:",
	} {
		if !strings.Contains(output, field) {
			t.Errorf("expected %q in YAML output", field)
		}
	}
	if strings.Contains(output, "unused_privileges:") {
		t.Error("YAML output contains obsolete unused_privileges field")
	}
}

func TestTerraformGenerator(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TerraformGenerator{}).Generate(testResults, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	for _, expected := range []string{
		"SHINKAI-SHOUJO REVIEW OUTPUT ONLY",
		"does not modify IAM",
		"Candidate-unused permissions require human review",
		"locals {",
		"shinkai_shoujo_review = [",
		`account_id = "123456789012"`,
		`iam_role = "arn:aws:iam::123456789012:role/MyRole"`,
		`risk_level = "MEDIUM"`,
		`observation_start = "2026-07-01T12:00:00Z"`,
		`analyzed_at = "2026-08-01T12:00:00.000000123Z"`,
		"used = [",
		"candidate_unused = [",
		"unresolved = [",
		"warnings = [",
		"usage = [",
		`action = "s3:GetObject"`,
		"successful_events = 12",
		"denied_events = 2",
		"failed_events = 1",
		`review $${candidate} and %%{directive}`,
	} {
		if !strings.Contains(output, expected) {
			t.Errorf("expected %q in Terraform output", expected)
		}
	}
	for _, forbidden := range []string{`resource "`, `provider "`, `data "`, `Resource = "*"`} {
		if strings.Contains(output, forbidden) {
			t.Errorf("Terraform review output contains forbidden text %q", forbidden)
		}
	}
	if strings.Count(output, "locals {") != 1 {
		t.Errorf("expected exactly one locals block, got output:\n%s", output)
	}
}

func TestTerraformGeneratorEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := (&TerraformGenerator{}).Generate(nil, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "locals {\n  shinkai_shoujo_review = []\n}\n") {
		t.Errorf("empty output does not contain a valid empty review local:\n%s", output)
	}
	if strings.Contains(output, `resource "`) || strings.Contains(output, `Resource = "*"`) {
		t.Errorf("empty output contains deployable IAM configuration:\n%s", output)
	}
}

func TestGeneratorsPropagateWriterErrors(t *testing.T) {
	wantErr := errors.New("write failed")
	for name, generator := range map[string]Generator{
		"json":      &JSONGenerator{},
		"yaml":      &YAMLGenerator{},
		"terraform": &TerraformGenerator{},
	} {
		t.Run(name, func(t *testing.T) {
			err := generator.Generate(testResults, errorWriter{err: wantErr})
			if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
				t.Fatalf("Generate() error = %v, want %v", err, wantErr)
			}
		})
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestTerraformResourceName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"arn:aws:iam::123:role/MyRole", "arn_aws_iam__123_role_myrole"},
		{"MyRole", "myrole"},
		{"my-role-name", "my_role_name"},
	}
	for _, tt := range tests {
		got := terraformResourceName(tt.input)
		if got != tt.expected {
			t.Errorf("terraformResourceName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNew(t *testing.T) {
	formats := []string{"terraform", "json", "yaml"}
	for _, format := range formats {
		generator, err := New(format)
		if err != nil {
			t.Errorf("New(%q) error: %v", format, err)
		}
		if generator == nil {
			t.Errorf("New(%q) returned nil generator", format)
		}
	}

	if _, err := New("invalid"); err == nil {
		t.Error("expected error for invalid format")
	}
}
