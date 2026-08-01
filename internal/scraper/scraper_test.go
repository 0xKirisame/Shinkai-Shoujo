package scraper

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
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

func TestParsePolicyDocumentDenyDoesNotSubtractAllow(t *testing.T) {
	// Raw JSON:
	// {"Version":"2012-10-17","Statement":[
	//   {"Effect":"Allow","Action":["s3:*","ec2:DescribeInstances"],"Resource":"*"},
	//   {"Effect":"Deny","Action":"ec2:DescribeInstances","Resource":"*"}
	// ]}
	// This is an action inventory, so Deny is not evaluated against Allow.
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
	if !found["ec2:DescribeInstances"] {
		t.Error("expected ec2:DescribeInstances to remain in the Allow action inventory")
	}
}

func TestParsePolicyDocumentSingletonStatement(t *testing.T) {
	document := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["S3:GetObject","s3:getobject"],"Resource":"*"}}`

	actions, err := parsePolicyDocument(document)
	if err != nil {
		t.Fatalf("parsePolicyDocument() error: %v", err)
	}
	if len(actions) != 1 || actions[0] != "s3:GetObject" {
		t.Fatalf("expected case-insensitively deduplicated [s3:GetObject], got %v", actions)
	}
}

func TestParsePolicyDocumentRejectsAllowNotAction(t *testing.T) {
	document := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":"iam:DeleteRole","Resource":"*"}}`

	_, err := parsePolicyDocument(document)
	if err == nil {
		t.Fatal("expected Allow with NotAction to fail")
	}
	if !strings.Contains(err.Error(), "NotAction") {
		t.Fatalf("expected a clear NotAction error, got %v", err)
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

func TestScrapeAllFailsWhenAnyRoleFails(t *testing.T) {
	client := &mockIAMClient{
		listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{{
				RoleName: aws.String("broken-role"),
				Arn:      aws.String("arn:aws:iam::123456789012:role/broken-role"),
			}}}, nil
		},
		listAttachedRolePolicies: func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return nil, errors.New("attached policy API failed")
		},
	}

	assignments, err := newTestScraper(client).ScrapeAll(context.Background())
	if err == nil {
		t.Fatal("expected ScrapeAll to fail")
	}
	if assignments != nil {
		t.Fatalf("expected no partial assignments, got %v", assignments)
	}
	if !strings.Contains(err.Error(), "broken-role") {
		t.Fatalf("expected role context in error, got %v", err)
	}
}

func TestScrapeRoleFailsClosedOnPolicyErrors(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*mockIAMClient)
		wantError string
	}{
		{
			name: "managed policy parse",
			configure: func(client *mockIAMClient) {
				client.listAttachedRolePolicies = func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
					return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{{PolicyArn: aws.String("arn:policy")}}}, nil
				}
				client.getPolicy = func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
					return &iam.GetPolicyOutput{Policy: &types.Policy{DefaultVersionId: aws.String("v7")}}, nil
				}
				client.getPolicyVersion = func(_ context.Context, input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
					if aws.ToString(input.VersionId) != "v7" {
						t.Fatalf("expected GetPolicy DefaultVersionId v7, got %q", aws.ToString(input.VersionId))
					}
					return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: aws.String("not-json")}}, nil
				}
			},
			wantError: "parsing policy version",
		},
		{
			name: "inline policy list",
			configure: func(client *mockIAMClient) {
				client.listRolePolicies = func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
					return nil, errors.New("inline list failed")
				}
			},
			wantError: "listing inline policies",
		},
		{
			name: "inline policy parse",
			configure: func(client *mockIAMClient) {
				client.listRolePolicies = func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
					return &iam.ListRolePoliciesOutput{PolicyNames: []string{"broken-inline"}}, nil
				}
				client.getRolePolicy = func(context.Context, *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
					return &iam.GetRolePolicyOutput{PolicyDocument: aws.String("not-json")}, nil
				}
			},
			wantError: "parsing inline policy broken-inline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockIAMClient{}
			tt.configure(client)

			_, err := newTestScraper(client).ScrapeRole(context.Background(), types.Role{RoleName: aws.String("test-role")})
			if err == nil {
				t.Fatal("expected ScrapeRole to fail")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected error containing %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestScrapeSnapshotPreservesPolicyProvenanceAndSemantics(t *testing.T) {
	const (
		accountID        = "123456789012"
		managedARN       = "arn:aws:iam::123456789012:policy/ManagedPolicy"
		boundaryARN      = "arn:aws:iam::123456789012:policy/BoundaryPolicy"
		managedDocument  = `{"Version":"2012-10-17","Statement":[{"Sid":"AllowRead","Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::bucket","arn:aws:s3:::bucket/*"],"Condition":{"ZTest":{"z":"last"},"ATest":{"a":"first"}}},{"Sid":"DenyExceptRead","Effect":"Deny","NotAction":"s3:GetObject","NotResource":"arn:aws:s3:::bucket/*"}]}`
		inlineDocument   = `{"Version":"2012-10-17","Statement":[{"Sid":"InlineNotAction","Effect":"Allow","NotAction":["iam:DeleteRole","iam:PassRole"],"Resource":"*"},{"Sid":"InlineDeny","Effect":"Deny","Action":"ec2:TerminateInstances","Resource":"*"}]}`
		boundaryDocument = `{"Version":"2012-10-17","Statement":{"Sid":"Boundary","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`
	)

	role := testRole("app-role", accountID)
	role.PermissionsBoundary = &types.AttachedPermissionsBoundary{PermissionsBoundaryArn: aws.String(boundaryARN)}
	client := &mockIAMClient{
		listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{role}}, nil
		},
		listAttachedRolePolicies: func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{{
				PolicyArn: aws.String(managedARN), PolicyName: aws.String("ManagedPolicy"),
			}}}, nil
		},
		listRolePolicies: func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"InlinePolicy"}}, nil
		},
		getRolePolicy: func(context.Context, *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
			return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(url.QueryEscape(inlineDocument))}, nil
		},
		getPolicy: func(_ context.Context, input *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			switch aws.ToString(input.PolicyArn) {
			case managedARN:
				return &iam.GetPolicyOutput{Policy: &types.Policy{PolicyName: aws.String("ManagedPolicy"), DefaultVersionId: aws.String("v3")}}, nil
			case boundaryARN:
				return &iam.GetPolicyOutput{Policy: &types.Policy{PolicyName: aws.String("BoundaryPolicy"), DefaultVersionId: aws.String("v8")}}, nil
			default:
				return nil, errors.New("unexpected policy ARN")
			}
		},
		getPolicyVersion: func(_ context.Context, input *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			var document string
			switch aws.ToString(input.PolicyArn) {
			case managedARN:
				if aws.ToString(input.VersionId) != "v3" {
					t.Fatalf("managed version = %q, want v3", aws.ToString(input.VersionId))
				}
				document = managedDocument
			case boundaryARN:
				if aws.ToString(input.VersionId) != "v8" {
					t.Fatalf("boundary version = %q, want v8", aws.ToString(input.VersionId))
				}
				document = boundaryDocument
			default:
				return nil, errors.New("unexpected policy ARN")
			}
			return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: aws.String(url.QueryEscape(document))}}, nil
		},
	}

	snapshot, err := newTestScraper(client).ScrapeSnapshot(context.Background(), "")
	if err != nil {
		t.Fatalf("ScrapeSnapshot() error: %v", err)
	}
	if snapshot.AccountID != accountID {
		t.Fatalf("AccountID = %q, want %q", snapshot.AccountID, accountID)
	}
	if len(snapshot.SnapshotID) != 32 {
		t.Fatalf("SnapshotID length = %d, want 32", len(snapshot.SnapshotID))
	}
	if decoded, err := hex.DecodeString(snapshot.SnapshotID); err != nil || len(decoded) != 16 {
		t.Fatalf("SnapshotID is not 128-bit hex: %q (%v)", snapshot.SnapshotID, err)
	}
	if snapshot.CollectedAt.Location() != time.UTC {
		t.Fatalf("CollectedAt location = %v, want UTC", snapshot.CollectedAt.Location())
	}
	if len(snapshot.Roles) != 1 {
		t.Fatalf("roles = %d, want 1", len(snapshot.Roles))
	}
	gotRole := snapshot.Roles[0]
	if gotRole.RoleARN != aws.ToString(role.Arn) || gotRole.RoleName != "app-role" || gotRole.RoleID != "ID-app-role" || gotRole.Path != "/application/" {
		t.Fatalf("role identity not preserved: %+v", gotRole)
	}
	if len(gotRole.Statements) != 5 {
		t.Fatalf("statements = %d, want 5: %+v", len(gotRole.Statements), gotRole.Statements)
	}

	managedAllow := gotRole.Statements[0]
	if managedAllow.Origin != storage.IAMStatementOriginManaged || managedAllow.PolicyARN != managedARN || managedAllow.PolicyName != "ManagedPolicy" || managedAllow.PolicyVersionID != "v3" {
		t.Fatalf("managed provenance not preserved: %+v", managedAllow)
	}
	if managedAllow.StatementID != "AllowRead" || managedAllow.Effect != "Allow" || !reflect.DeepEqual(managedAllow.Actions, []string{"s3:GetObject", "s3:ListBucket"}) || !reflect.DeepEqual(managedAllow.Resources, []string{"arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"}) {
		t.Fatalf("managed statement semantics not preserved: %+v", managedAllow)
	}
	if managedAllow.ConditionJSON != `{"ATest":{"a":"first"},"ZTest":{"z":"last"}}` {
		t.Fatalf("ConditionJSON = %q", managedAllow.ConditionJSON)
	}
	if managedAllow.RawDocument != managedDocument {
		t.Fatalf("RawDocument was not URL-decoded: %q", managedAllow.RawDocument)
	}

	managedDeny := gotRole.Statements[1]
	if managedDeny.Effect != "Deny" || !reflect.DeepEqual(managedDeny.NotActions, []string{"s3:GetObject"}) || !reflect.DeepEqual(managedDeny.NotResources, []string{"arn:aws:s3:::bucket/*"}) {
		t.Fatalf("managed Deny/NotAction semantics not preserved: %+v", managedDeny)
	}
	inlineAllow := gotRole.Statements[2]
	if inlineAllow.Origin != storage.IAMStatementOriginInline || inlineAllow.PolicyARN != "" || inlineAllow.PolicyName != "InlinePolicy" || inlineAllow.PolicyVersionID != "" || !reflect.DeepEqual(inlineAllow.NotActions, []string{"iam:DeleteRole", "iam:PassRole"}) {
		t.Fatalf("inline provenance/NotAction not preserved: %+v", inlineAllow)
	}
	if inlineAllow.RawDocument != inlineDocument || gotRole.Statements[3].Effect != "Deny" {
		t.Fatalf("inline document or Deny not preserved: %+v", gotRole.Statements[2:4])
	}
	boundary := gotRole.Statements[4]
	if boundary.Origin != storage.IAMStatementOriginBoundary || boundary.PolicyARN != boundaryARN || boundary.PolicyName != "BoundaryPolicy" || boundary.PolicyVersionID != "v8" || boundary.StatementID != "Boundary" {
		t.Fatalf("boundary provenance not preserved: %+v", boundary)
	}
}

func TestScrapeSnapshotCachesSharedManagedPolicy(t *testing.T) {
	const (
		accountID = "123456789012"
		policyARN = "arn:aws:iam::123456789012:policy/Shared"
		document  = `{"Statement":{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}}`
	)
	var getPolicyCalls atomic.Int32
	var getVersionCalls atomic.Int32
	client := &mockIAMClient{
		listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{testRole("role-b", accountID), testRole("role-a", accountID)}}, nil
		},
		listAttachedRolePolicies: func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []types.AttachedPolicy{{PolicyArn: aws.String(policyARN), PolicyName: aws.String("Shared")}}}, nil
		},
		getPolicy: func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error) {
			getPolicyCalls.Add(1)
			return &iam.GetPolicyOutput{Policy: &types.Policy{PolicyName: aws.String("Shared"), DefaultVersionId: aws.String("v4")}}, nil
		},
		getPolicyVersion: func(context.Context, *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
			getVersionCalls.Add(1)
			return &iam.GetPolicyVersionOutput{PolicyVersion: &types.PolicyVersion{Document: aws.String(document)}}, nil
		},
	}

	snapshot, err := newTestScraper(client).ScrapeSnapshot(context.Background(), accountID)
	if err != nil {
		t.Fatalf("ScrapeSnapshot() error: %v", err)
	}
	if getPolicyCalls.Load() != 1 || getVersionCalls.Load() != 1 {
		t.Fatalf("shared policy fetched %d/%d times, want 1/1", getPolicyCalls.Load(), getVersionCalls.Load())
	}
	if len(snapshot.Roles) != 2 || snapshot.Roles[0].RoleName != "role-a" || snapshot.Roles[1].RoleName != "role-b" {
		t.Fatalf("roles are not deterministic: %+v", snapshot.Roles)
	}
	for _, role := range snapshot.Roles {
		if len(role.Statements) != 1 || role.Statements[0].PolicyVersionID != "v4" {
			t.Fatalf("cached policy missing from role %s: %+v", role.RoleName, role.Statements)
		}
	}
}

func TestScrapeSnapshotAccountValidation(t *testing.T) {
	t.Run("derives consistent account", func(t *testing.T) {
		client := &mockIAMClient{listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{testRole("role-b", "210987654321"), testRole("role-a", "210987654321")}}, nil
		}}
		snapshot, err := newTestScraper(client).ScrapeSnapshot(context.Background(), "")
		if err != nil {
			t.Fatalf("ScrapeSnapshot() error: %v", err)
		}
		if snapshot.AccountID != "210987654321" {
			t.Fatalf("AccountID = %q", snapshot.AccountID)
		}
	})

	for _, tt := range []struct {
		name      string
		accountID string
		roles     []types.Role
	}{
		{name: "supplied mismatch", accountID: "123456789012", roles: []types.Role{testRole("other", "210987654321")}},
		{name: "inconsistent derivation", roles: []types.Role{testRole("one", "123456789012"), testRole("two", "210987654321")}},
		{name: "impossible derivation"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockIAMClient{listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
				return &iam.ListRolesOutput{Roles: tt.roles}, nil
			}}
			snapshot, err := newTestScraper(client).ScrapeSnapshot(context.Background(), tt.accountID)
			if err == nil {
				t.Fatal("expected account validation error")
			}
			if !reflect.DeepEqual(snapshot, storage.IAMSnapshot{}) {
				t.Fatalf("expected no partial snapshot, got %+v", snapshot)
			}
		})
	}
}

func TestScrapeSnapshotSingletonInlineStatement(t *testing.T) {
	const document = `{"Statement":{"Sid":"Only","Effect":"Deny","Action":"kms:Decrypt","NotResource":["arn:aws:kms:*:123456789012:key/safe"]}}`
	client := &mockIAMClient{
		listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{testRole("singleton", "123456789012")}}, nil
		},
		listRolePolicies: func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"only-inline"}}, nil
		},
		getRolePolicy: func(context.Context, *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
			return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(document)}, nil
		},
	}
	snapshot, err := newTestScraper(client).ScrapeSnapshot(context.Background(), "123456789012")
	if err != nil {
		t.Fatalf("ScrapeSnapshot() error: %v", err)
	}
	statement := snapshot.Roles[0].Statements[0]
	if statement.StatementID != "Only" || statement.Effect != "Deny" || !reflect.DeepEqual(statement.Actions, []string{"kms:Decrypt"}) || !reflect.DeepEqual(statement.NotResources, []string{"arn:aws:kms:*:123456789012:key/safe"}) {
		t.Fatalf("singleton statement not preserved: %+v", statement)
	}
}

func TestScrapeSnapshotFailsClosedOnPartialRoleFailure(t *testing.T) {
	client := &mockIAMClient{
		listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{testRole("good", "123456789012"), testRole("broken", "123456789012")}}, nil
		},
		listAttachedRolePolicies: func(_ context.Context, input *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error) {
			if aws.ToString(input.RoleName) == "broken" {
				return nil, errors.New("attached list failed")
			}
			return &iam.ListAttachedRolePoliciesOutput{}, nil
		},
	}

	snapshot, err := newTestScraper(client).ScrapeSnapshot(context.Background(), "123456789012")
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("expected broken role error, got %v", err)
	}
	if !reflect.DeepEqual(snapshot, storage.IAMSnapshot{}) {
		t.Fatalf("expected no partial snapshot, got %+v", snapshot)
	}
}

func TestScrapeSnapshotRejectsMalformedStatementValue(t *testing.T) {
	client := &mockIAMClient{
		listRoles: func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error) {
			return &iam.ListRolesOutput{Roles: []types.Role{testRole("broken", "123456789012")}}, nil
		},
		listRolePolicies: func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error) {
			return &iam.ListRolePoliciesOutput{PolicyNames: []string{"malformed"}}, nil
		},
		getRolePolicy: func(context.Context, *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
			return &iam.GetRolePolicyOutput{PolicyDocument: aws.String(`{"Statement":{"Effect":"Allow","Action":{"bad":true},"Resource":"*"}}`)}, nil
		},
	}
	if _, err := newTestScraper(client).ScrapeSnapshot(context.Background(), "123456789012"); err == nil || !strings.Contains(err.Error(), "Action") {
		t.Fatalf("expected malformed Action error, got %v", err)
	}
}

func testRole(name, accountID string) types.Role {
	return types.Role{
		Arn:      aws.String("arn:aws:iam::" + accountID + ":role/application/" + name),
		RoleName: aws.String(name),
		RoleId:   aws.String("ID-" + name),
		Path:     aws.String("/application/"),
	}
}

func newTestScraper(client iamClient) *Scraper {
	return &Scraper{
		client: client,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

type mockIAMClient struct {
	listRoles                func(context.Context, *iam.ListRolesInput) (*iam.ListRolesOutput, error)
	listAttachedRolePolicies func(context.Context, *iam.ListAttachedRolePoliciesInput) (*iam.ListAttachedRolePoliciesOutput, error)
	getPolicy                func(context.Context, *iam.GetPolicyInput) (*iam.GetPolicyOutput, error)
	getPolicyVersion         func(context.Context, *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error)
	listRolePolicies         func(context.Context, *iam.ListRolePoliciesInput) (*iam.ListRolePoliciesOutput, error)
	getRolePolicy            func(context.Context, *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error)
}

func (m *mockIAMClient) ListRoles(ctx context.Context, input *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.listRoles != nil {
		return m.listRoles(ctx, input)
	}
	return &iam.ListRolesOutput{}, nil
}

func (m *mockIAMClient) ListAttachedRolePolicies(ctx context.Context, input *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if m.listAttachedRolePolicies != nil {
		return m.listAttachedRolePolicies(ctx, input)
	}
	return &iam.ListAttachedRolePoliciesOutput{}, nil
}

func (m *mockIAMClient) GetPolicy(ctx context.Context, input *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	if m.getPolicy != nil {
		return m.getPolicy(ctx, input)
	}
	return &iam.GetPolicyOutput{}, nil
}

func (m *mockIAMClient) GetPolicyVersion(ctx context.Context, input *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if m.getPolicyVersion != nil {
		return m.getPolicyVersion(ctx, input)
	}
	return &iam.GetPolicyVersionOutput{}, nil
}

func (m *mockIAMClient) ListRolePolicies(ctx context.Context, input *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	if m.listRolePolicies != nil {
		return m.listRolePolicies(ctx, input)
	}
	return &iam.ListRolePoliciesOutput{}, nil
}

func (m *mockIAMClient) GetRolePolicy(ctx context.Context, input *iam.GetRolePolicyInput, _ ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	if m.getRolePolicy != nil {
		return m.getRolePolicy(ctx, input)
	}
	return &iam.GetRolePolicyOutput{}, nil
}
