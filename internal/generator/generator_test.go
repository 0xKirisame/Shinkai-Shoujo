package generator

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
)

var testResults = []correlation.Result{
	{
		IAMRole:    "arn:aws:iam::123456789012:role/MyRole",
		Assigned:   []string{"s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"},
		Used:       []string{"s3:GetObject"},
		Unused:     []string{"s3:PutObject", "ec2:DescribeInstances"},
		RiskLevel:  "MEDIUM",
		AnalyzedAt: time.Now(),
	},
	{
		IAMRole:    "arn:aws:iam::123456789012:role/ReadOnlyRole",
		Assigned:   []string{"s3:GetObject"},
		Used:       []string{"s3:GetObject"},
		Unused:     []string{},
		RiskLevel:  "LOW",
		AnalyzedAt: time.Now(),
	},
}

func TestJSONGenerator(t *testing.T) {
	g := &JSONGenerator{}
	var buf bytes.Buffer
	if err := g.Generate(testResults, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(report.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(report.Roles))
	}
	if report.Roles[0].UnusedCount != 2 {
		t.Errorf("expected 2 unused for MyRole, got %d", report.Roles[0].UnusedCount)
	}
	if report.Roles[1].UnusedCount != 0 {
		t.Errorf("expected 0 unused for ReadOnlyRole, got %d", report.Roles[1].UnusedCount)
	}
}

func TestYAMLGenerator(t *testing.T) {
	g := &YAMLGenerator{}
	var buf bytes.Buffer
	if err := g.Generate(testResults, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "iam_role:") {
		t.Error("expected 'iam_role:' in YAML output")
	}
	if !strings.Contains(output, "unused_privileges:") {
		t.Error("expected 'unused_privileges:' in YAML output")
	}
}

func TestTerraformGenerator(t *testing.T) {
	g := &TerraformGenerator{}
	var buf bytes.Buffer
	if err := g.Generate(testResults, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `resource "aws_iam_policy"`) {
		t.Error("expected Terraform resource block in output")
	}
	if !strings.Contains(output, "No unused privileges") {
		t.Error("expected comment for role with no unused privileges")
	}
}

func TestTerraformGenerator_EmptyUsed(t *testing.T) {
	// Role has assigned privileges but zero OTel observations — used list is empty.
	// Must NOT generate an empty Action = [] block (invalid HCL).
	results := []correlation.Result{
		{
			IAMRole:    "arn:aws:iam::123:role/NeverObserved",
			Assigned:   []string{"s3:GetObject", "s3:PutObject"},
			Used:       []string{},
			Unused:     []string{"s3:GetObject", "s3:PutObject"},
			RiskLevel:  "MEDIUM",
			AnalyzedAt: time.Now(),
		},
	}

	g := &TerraformGenerator{}
	var buf bytes.Buffer
	if err := g.Generate(results, &buf); err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Action = [") {
		t.Error("must not emit Action block when used list is empty")
	}
	if !strings.Contains(output, "WARNING") {
		t.Error("expected WARNING comment for unobserved role")
	}
}

func TestTerraformResourceName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"arn:aws:iam::123:role/MyRole", "arn_aws_iam_123_role_myrole"},
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
	for _, f := range formats {
		g, err := New(f)
		if err != nil {
			t.Errorf("New(%q) error: %v", f, err)
		}
		if g == nil {
			t.Errorf("New(%q) returned nil generator", f)
		}
	}

	_, err := New("invalid")
	if err == nil {
		t.Error("expected error for invalid format")
	}
}
