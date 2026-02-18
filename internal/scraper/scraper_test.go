package scraper

import (
	"testing"
)

func TestParsePolicyDocument(t *testing.T) {
	// URL-encoded JSON policy document (as returned by AWS GetPolicyVersion)
	// The raw JSON is:
	// {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}
	encoded := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22s3%3AGetObject%22%2C%22s3%3APutObject%22%5D%2C%22Resource%22%3A%22%2A%22%7D%2C%7B%22Effect%22%3A%22Deny%22%2C%22Action%22%3A%22s3%3ADeleteObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"

	actions, err := parsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parsePolicyDocument() error: %v", err)
	}

	// Should only include Allow actions
	if len(actions) != 2 {
		t.Errorf("expected 2 actions, got %d: %v", len(actions), actions)
	}

	found := map[string]bool{}
	for _, a := range actions {
		found[a] = true
	}
	if !found["s3:GetObject"] {
		t.Error("expected s3:GetObject in actions")
	}
	if !found["s3:PutObject"] {
		t.Error("expected s3:PutObject in actions")
	}
	if found["s3:DeleteObject"] {
		t.Error("Deny action s3:DeleteObject should not be included")
	}
}

func TestParsePolicyDocumentDenyCoverage(t *testing.T) {
	// Raw JSON:
	// {"Version":"2012-10-17","Statement":[
	//   {"Effect":"Allow","Action":["s3:*","ec2:DescribeInstances"],"Resource":"*"},
	//   {"Effect":"Deny","Action":"ec2:DescribeInstances","Resource":"*"}
	// ]}
	// Allow "s3:*" and "ec2:DescribeInstances", but Deny "ec2:DescribeInstances".
	// Expected result: ["s3:*"] — ec2:DescribeInstances is removed by the deny.
	encoded := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22s3%3A%2A%22%2C%22ec2%3ADescribeInstances%22%5D%2C%22Resource%22%3A%22%2A%22%7D%2C%7B%22Effect%22%3A%22Deny%22%2C%22Action%22%3A%22ec2%3ADescribeInstances%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"

	actions, err := parsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parsePolicyDocument() error: %v", err)
	}

	found := map[string]bool{}
	for _, a := range actions {
		found[a] = true
	}
	if !found["s3:*"] {
		t.Error("expected s3:* to be present (allow wildcard not split by specific deny)")
	}
	if found["ec2:DescribeInstances"] {
		t.Error("ec2:DescribeInstances should be excluded by the Deny statement")
	}
}

func TestParsePolicyDocumentWildcard(t *testing.T) {
	// Policy with wildcard action: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}
	encoded := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3A%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"

	actions, err := parsePolicyDocument(encoded)
	if err != nil {
		t.Fatalf("parsePolicyDocument() error: %v", err)
	}
	if len(actions) != 1 || actions[0] != "s3:*" {
		t.Errorf("expected [s3:*], got %v", actions)
	}
}

func TestActionValueUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"string", `"s3:GetObject"`, []string{"s3:GetObject"}},
		{"array", `["s3:GetObject","s3:PutObject"]`, []string{"s3:GetObject", "s3:PutObject"}},
		{"wildcard", `"s3:*"`, []string{"s3:*"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var av ActionValue
			if err := av.UnmarshalJSON([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalJSON() error: %v", err)
			}
			if len(av) != len(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, av)
				return
			}
			for i, v := range av {
				if v != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, av)
				}
			}
		})
	}
}

func TestNormalizeAction(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"S3:GetObject", "s3:GetObject"},
		{"s3:GetObject", "s3:GetObject"},
		{"IAM:CreateRole", "iam:CreateRole"},
		{"*", "*"},
		{"s3:*", "s3:*"},
	}
	for _, tt := range tests {
		got := normalizeAction(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeAction(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
