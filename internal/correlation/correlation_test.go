package correlation

import (
	"testing"
)

// --- Risk classification tests ---

func TestClassifyPrivilege(t *testing.T) {
	tests := []struct {
		privilege string
		expected  RiskLevel
	}{
		{"s3:DeleteObject", RiskHigh},
		{"ec2:TerminateInstances", RiskHigh},
		{"s3:GetObject", RiskLow},
		{"iam:ListRoles", RiskLow},
		{"ec2:DescribeInstances", RiskLow},
		{"s3:PutObject", RiskMedium},
		{"iam:CreateRole", RiskMedium},
		{"ec2:ModifyInstanceAttribute", RiskMedium},
		{"s3:*", RiskMedium},  // wildcard
		{"*", RiskMedium},     // global wildcard
		{"s3:UnknownAction", RiskMedium}, // default
	}

	for _, tt := range tests {
		got := ClassifyPrivilege(tt.privilege)
		if got != tt.expected {
			t.Errorf("ClassifyPrivilege(%q) = %v, want %v", tt.privilege, got, tt.expected)
		}
	}
}

func TestClassifySet(t *testing.T) {
	tests := []struct {
		name      string
		privs     []string
		expected  RiskLevel
	}{
		{"empty", []string{}, RiskLow},
		{"all low", []string{"s3:GetObject", "ec2:DescribeInstances"}, RiskLow},
		{"mixed medium", []string{"s3:GetObject", "s3:PutObject"}, RiskMedium},
		{"has high", []string{"s3:GetObject", "s3:DeleteObject"}, RiskHigh},
		{"single high", []string{"ec2:TerminateInstances"}, RiskHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifySet(tt.privs)
			if got != tt.expected {
				t.Errorf("ClassifySet(%v) = %v, want %v", tt.privs, got, tt.expected)
			}
		})
	}
}

// --- Set difference tests ---

func TestSetDifference_ExactMatch(t *testing.T) {
	assigned := []string{"s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"}
	used := []string{"s3:GetObject"}
	unused := setDifference(assigned, used)

	if len(unused) != 2 {
		t.Errorf("expected 2 unused, got %d: %v", len(unused), unused)
	}
}

func TestSetDifference_ServiceWildcardAssigned(t *testing.T) {
	// "s3:*" is assigned, and "s3:GetObject" was observed → wildcard is "used"
	assigned := []string{"s3:*", "ec2:DescribeInstances"}
	used := []string{"s3:GetObject"}
	unused := setDifference(assigned, used)

	// s3:* should be considered used, ec2:DescribeInstances is unused
	if len(unused) != 1 || unused[0] != "ec2:DescribeInstances" {
		t.Errorf("expected [ec2:DescribeInstances], got %v", unused)
	}
}

func TestSetDifference_ServiceWildcardUsed(t *testing.T) {
	// "s3:GetObject" is assigned, and "s3:*" was observed → specific action is covered
	assigned := []string{"s3:GetObject", "ec2:DescribeInstances"}
	used := []string{"s3:*"}
	unused := setDifference(assigned, used)

	// s3:GetObject is covered by s3:*, only ec2:DescribeInstances is unused
	if len(unused) != 1 || unused[0] != "ec2:DescribeInstances" {
		t.Errorf("expected [ec2:DescribeInstances], got %v", unused)
	}
}

func TestSetDifference_GlobalWildcardUsed(t *testing.T) {
	assigned := []string{"s3:GetObject", "ec2:DescribeInstances"}
	used := []string{"*"}
	unused := setDifference(assigned, used)
	if len(unused) != 0 {
		t.Errorf("expected empty unused when '*' was used, got %v", unused)
	}
}

func TestSetDifference_GlobalWildcardAssigned(t *testing.T) {
	// "*" is assigned and some privilege was observed → wildcard is used
	assigned := []string{"*"}
	used := []string{"s3:GetObject"}
	unused := setDifference(assigned, used)
	if len(unused) != 0 {
		t.Errorf("expected empty unused when '*' assigned and used, got %v", unused)
	}
}

func TestSetDifference_GlobalWildcardAssignedNoUsed(t *testing.T) {
	// "*" is assigned but nothing was observed → it's unused
	assigned := []string{"*"}
	used := []string{}
	unused := setDifference(assigned, used)
	if len(unused) != 1 {
		t.Errorf("expected ['*'] unused, got %v", unused)
	}
}

func TestSetDifference_EmptyAssigned(t *testing.T) {
	unused := setDifference(nil, []string{"s3:GetObject"})
	if len(unused) != 0 {
		t.Errorf("expected empty, got %v", unused)
	}
}

// --- SDK mapping tests ---

func TestMapSDKToIAM(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"lambda:Invoke", "lambda:InvokeFunction"},
		{"lambda:InvokeAsync", "lambda:InvokeFunction"},
		{"ec2:StartInstance", "ec2:StartInstances"},
		{"ec2:StopInstance", "ec2:StopInstances"},
		{"s3:GetObject", "s3:GetObject"}, // no mapping, passthrough
		{"unknown:SomeOp", "unknown:SomeOp"},
	}

	for _, tt := range tests {
		got := MapSDKToIAM(tt.input)
		if got != tt.expected {
			t.Errorf("MapSDKToIAM(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
