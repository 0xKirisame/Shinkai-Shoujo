package correlation

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	testTenant  = "tenant-1"
	testAccount = "123456789012"
)

type fakeUsageStore struct {
	usage               []storage.PermissionUsage
	err                 error
	query               storage.UsageQuery
	coverage            storage.CollectorCoverage
	coverageSet         bool
	coverageErr         error
	coverageWindowStart time.Time
}

func (f *fakeUsageStore) GetCollectorCoverage(_ context.Context, since time.Time) (storage.CollectorCoverage, error) {
	f.coverageWindowStart = since
	if !f.coverageSet {
		return storage.CollectorCoverage{
			FirstHeartbeat: since,
			LastHeartbeat:  time.Now().UTC(),
			Received:       1,
			Accepted:       1,
		}, f.coverageErr
	}
	return f.coverage, f.coverageErr
}

func (f *fakeUsageStore) QueryPermissionUsage(_ context.Context, query storage.UsageQuery) ([]storage.PermissionUsage, error) {
	f.query = query
	return append([]storage.PermissionUsage(nil), f.usage...), f.err
}

func TestEngineRunExactUsedAndUnused(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	firstSuccess := now.Add(-8 * 24 * time.Hour)
	roleARN := roleARN("Exact")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{
		{
			RoleARN:          roleARN,
			IAMAction:        "s3:GetObject",
			SuccessfulEvents: 3,
			DeniedEvents:     1,
			FirstSuccess:     firstSuccess,
			LastSuccess:      now,
		},
	}}
	engine := newTestEngine(store)
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN:  roleARN,
		RoleName: "Exact",
		Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginManaged, "s3:PutObject", "s3:GetObject"),
		},
	})

	results, err := engine.Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %#v, want one role", results)
	}
	result := results[0]
	assertStrings(t, result.Assigned, "s3:GetObject", "s3:PutObject")
	assertStrings(t, result.Used, "s3:GetObject")
	assertStrings(t, result.Unused, "s3:PutObject")
	assertStrings(t, result.Unresolved)
	if result.AccountID != testAccount || result.IAMRole != roleARN {
		t.Fatalf("unexpected result identity: %#v", result)
	}
	if len(result.Usage) != 1 || result.Usage[0].SuccessfulEvents != 3 || result.Usage[0].DeniedEvents != 1 {
		t.Fatalf("unexpected usage aggregate: %#v", result.Usage)
	}
	if !result.Usage[0].FirstSuccess.Equal(firstSuccess) || !result.Usage[0].LastSuccess.Equal(now) {
		t.Fatalf("unexpected success range: %#v", result.Usage[0])
	}
	if store.query.TenantID != testTenant || store.query.AccountID != testAccount {
		t.Fatalf("unexpected usage query scope: %#v", store.query)
	}
	if !store.query.Since.Equal(result.ObservationStart) || !store.query.Until.Equal(result.AnalyzedAt) {
		t.Fatalf("query window %#v does not match result window", store.query)
	}
	if !store.coverageWindowStart.Equal(result.ObservationStart) {
		t.Fatalf("coverage window starts at %s, want %s", store.coverageWindowStart, result.ObservationStart)
	}
	if got := result.AnalyzedAt.Sub(result.ObservationStart); got < 29*24*time.Hour || got > 31*24*time.Hour {
		t.Fatalf("observation window = %s, want approximately 30 days", got)
	}
}

func TestEngineRunSuppressesUnusedUntilCoverageIsSufficient(t *testing.T) {
	roleARN := roleARN("Coverage")
	tests := []struct {
		name             string
		firstHeartbeat   time.Time
		wantUnused       []string
		wantUnresolved   []string
		wantWarningParts []string
	}{
		{
			name:             "no coverage",
			wantUnresolved:   []string{"s3:PutObject"},
			wantWarningParts: []string{"observed collection duration is 0.0 days", "required duration is 7 days"},
		},
		{
			name:             "short coverage",
			firstHeartbeat:   time.Now().UTC().Add(-48 * time.Hour),
			wantUnresolved:   []string{"s3:PutObject"},
			wantWarningParts: []string{"observed collection duration is 2.0 days", "required duration is 7 days"},
		},
		{
			name:           "sufficient coverage",
			firstHeartbeat: time.Now().UTC().Add(-8 * 24 * time.Hour),
			wantUnused:     []string{"s3:PutObject"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstSuccess := time.Now().UTC().Add(-8 * 24 * time.Hour)
			store := &fakeUsageStore{
				usage: []storage.PermissionUsage{{
					RoleARN: roleARN, IAMAction: "s3:GetObject", SuccessfulEvents: 2, FirstSuccess: firstSuccess,
				}},
				coverage: storage.CollectorCoverage{
					FirstHeartbeat: test.firstHeartbeat,
					LastHeartbeat:  time.Now().UTC(),
					Received:       3,
					Accepted:       2,
				},
				coverageSet: true,
			}
			snapshot := snapshotWithRoles(storage.IAMRole{
				RoleARN: roleARN,
				Statements: []storage.IAMPolicyStatement{
					allow(storage.IAMStatementOriginManaged, "s3:GetObject", "s3:PutObject"),
				},
			})

			results, err := newTestEngine(store).Run(context.Background(), snapshot)
			if err != nil {
				t.Fatal(err)
			}
			result := results[0]
			assertStrings(t, result.Used, "s3:GetObject")
			assertStrings(t, result.Unused, test.wantUnused...)
			assertStrings(t, result.Unresolved, test.wantUnresolved...)
			if len(result.Usage) != 1 || result.Usage[0].SuccessfulEvents != 2 {
				t.Fatalf("usage was not preserved: %#v", result.Usage)
			}
			for _, part := range test.wantWarningParts {
				assertWarningContains(t, result.Warnings, part)
			}
			if len(test.wantWarningParts) == 0 && len(result.Warnings) != 0 {
				t.Fatalf("unexpected warnings with sufficient coverage: %#v", result.Warnings)
			}
		})
	}
}

func TestEngineRunNewlyObservedRoleDoesNotInheritGlobalCoverageAge(t *testing.T) {
	now := time.Now().UTC()
	roleARN := roleARN("NewRole")
	store := &fakeUsageStore{
		usage: []storage.PermissionUsage{{
			RoleARN:          roleARN,
			IAMAction:        "s3:GetObject",
			SuccessfulEvents: 1,
			FirstSuccess:     now.Add(-2 * 24 * time.Hour),
			LastSuccess:      now,
		}},
		coverage: storage.CollectorCoverage{
			FirstHeartbeat: now.Add(-20 * 24 * time.Hour),
			LastHeartbeat:  now,
			Received:       1,
			Accepted:       1,
		},
		coverageSet: true,
	}
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginManaged, "s3:GetObject", "s3:PutObject"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Used, "s3:GetObject")
	assertStrings(t, result.Unused)
	assertStrings(t, result.Unresolved, "s3:PutObject")
	assertWarningContains(t, result.Warnings, "observed collection duration is 2.0 days")
	if len(result.Usage) != 1 || !result.Usage[0].FirstSuccess.Equal(now.Add(-2*24*time.Hour)) {
		t.Fatalf("usage was not preserved: %#v", result.Usage)
	}
}

func TestEngineRunSuppressesUnusedWhenCollectorHeartbeatIsStale(t *testing.T) {
	now := time.Now().UTC()
	roleARN := roleARN("StaleCoverage")
	store := &fakeUsageStore{
		usage: []storage.PermissionUsage{{
			RoleARN:          roleARN,
			IAMAction:        "s3:GetObject",
			SuccessfulEvents: 1,
			FirstSuccess:     now.Add(-8 * 24 * time.Hour),
			LastSuccess:      now,
		}},
		coverage: storage.CollectorCoverage{
			FirstHeartbeat: now.Add(-20 * 24 * time.Hour),
			LastHeartbeat:  now.Add(-25 * time.Hour),
			Received:       1,
			Accepted:       1,
		},
		coverageSet: true,
	}
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginManaged, "s3:GetObject", "s3:PutObject"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Used, "s3:GetObject")
	assertStrings(t, result.Unused)
	assertStrings(t, result.Unresolved, "s3:PutObject")
	assertWarningContains(t, result.Warnings, "coverage is stale")
	if len(result.Usage) != 1 || result.Usage[0].SuccessfulEvents != 1 {
		t.Fatalf("usage was not preserved: %#v", result.Usage)
	}
}

func TestEngineRunWildcardRemainsUnresolved(t *testing.T) {
	roleARN := roleARN("Wildcard")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{{
		RoleARN: roleARN, IAMAction: "S3:getObject", SuccessfulEvents: 1,
		FirstSuccess: time.Now().UTC().Add(-8 * 24 * time.Hour),
	}}}
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginInline, "s3:Get?bject", "ec2:DescribeInstances"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Used, "S3:getObject")
	assertStrings(t, result.Unused, "ec2:DescribeInstances")
	assertStrings(t, result.Unresolved, "s3:Get?bject")
	if result.RiskLevel != string(RiskHigh) {
		t.Fatalf("wildcard risk = %q, want HIGH", result.RiskLevel)
	}
}

func TestEngineRunOmitsRoleWithoutEvents(t *testing.T) {
	observedARN := roleARN("Observed")
	unobservedARN := roleARN("InfrastructureOnly")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{{
		RoleARN: observedARN, IAMAction: "s3:GetObject", DeniedEvents: 1,
	}}}
	snapshot := snapshotWithRoles(
		storage.IAMRole{RoleARN: unobservedARN, Statements: []storage.IAMPolicyStatement{allow(storage.IAMStatementOriginManaged, "iam:PassRole")}},
		storage.IAMRole{RoleARN: observedARN, Statements: []storage.IAMPolicyStatement{allow(storage.IAMStatementOriginManaged, "s3:GetObject")}},
	)

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].IAMRole != observedARN {
		t.Fatalf("expected only role with an event aggregate, got %#v", results)
	}
}

func TestEngineRunDeniedAndFailedSuppressUnusedWithoutSuccessfulObservation(t *testing.T) {
	roleARN := roleARN("Outcomes")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{
		{RoleARN: roleARN, IAMAction: "s3:GetObject", DeniedEvents: 2},
		{RoleARN: roleARN, IAMAction: "s3:PutObject", FailedEvents: 4},
	}}
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginManaged, "s3:GetObject", "s3:PutObject"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Used)
	assertStrings(t, result.Unused)
	assertStrings(t, result.Unresolved, "s3:GetObject", "s3:PutObject")
	assertWarningContains(t, result.Warnings, "observed collection duration is 0.0 days")
	if len(result.Usage) != 2 || result.Usage[0].DeniedEvents != 2 || result.Usage[1].FailedEvents != 4 {
		t.Fatalf("denied and failed aggregates were not preserved: %#v", result.Usage)
	}
}

func TestEngineRunUncoveredSuccessSuppressesUnused(t *testing.T) {
	roleARN := roleARN("Drift")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{
		{RoleARN: roleARN, IAMAction: "sqs:SendMessage", SuccessfulEvents: 1, FirstSuccess: time.Now().UTC().Add(-8 * 24 * time.Hour)},
		{RoleARN: roleARN, IAMAction: "S3:getobject", SuccessfulEvents: 1, FirstSuccess: time.Now().UTC().Add(-8 * 24 * time.Hour)},
	}}
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginManaged, "s3:GetObject", "s3:PutObject"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Used, "S3:getobject")
	assertStrings(t, result.Unused)
	assertStrings(t, result.Unresolved, "s3:PutObject", "sqs:SendMessage")
	assertWarningContains(t, result.Warnings, "unused candidates suppressed")
}

func TestEngineRunBoundaryDoesNotGrant(t *testing.T) {
	roleARN := roleARN("Boundary")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{{
		RoleARN: roleARN, IAMAction: "s3:GetObject", SuccessfulEvents: 1,
		FirstSuccess: time.Now().UTC().Add(-8 * 24 * time.Hour),
	}}}
	boundary := allow(storage.IAMStatementOriginBoundary, "iam:PassRole")
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			boundary,
			allow(storage.IAMStatementOriginManaged, "s3:GetObject", "s3:PutObject"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Assigned, "s3:GetObject", "s3:PutObject")
	assertStrings(t, result.Used, "s3:GetObject")
	assertStrings(t, result.Unused, "s3:PutObject")
	assertWarningContains(t, result.Warnings, "boundary")
}

func TestEngineRunWarnsForConditionsDenyAndNotAction(t *testing.T) {
	roleARN := roleARN("Semantics")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{{
		RoleARN: roleARN, IAMAction: "s3:GetObject", DeniedEvents: 1,
	}}}
	conditional := allow(storage.IAMStatementOriginManaged, "s3:GetObject")
	conditional.ConditionJSON = `{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`
	deny := storage.IAMPolicyStatement{
		Origin:  storage.IAMStatementOriginInline,
		Effect:  "Deny",
		Actions: []string{"s3:DeleteObject"},
	}
	notAction := storage.IAMPolicyStatement{
		Origin:     storage.IAMStatementOriginInline,
		Effect:     "Allow",
		NotActions: []string{"iam:*", "IAM:*"},
	}
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN:    roleARN,
		Statements: []storage.IAMPolicyStatement{notAction, deny, conditional},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Assigned, "s3:GetObject")
	assertStrings(t, result.Unused)
	assertStrings(t, result.Unresolved, "IAM:*", "s3:GetObject")
	assertWarningContains(t, result.Warnings, "condition")
	assertWarningContains(t, result.Warnings, "Deny")
	assertWarningContains(t, result.Warnings, "NotAction")
}

func TestEngineRunConditionalExactActionIsUnresolved(t *testing.T) {
	roleARN := roleARN("Conditional")
	store := &fakeUsageStore{usage: []storage.PermissionUsage{{
		RoleARN: roleARN, IAMAction: "s3:GetObject", SuccessfulEvents: 1,
		FirstSuccess: time.Now().UTC().Add(-8 * 24 * time.Hour),
	}}}
	conditional := allow(storage.IAMStatementOriginInline, "s3:GetObject")
	conditional.ConditionJSON = `{"StringEquals":{"s3:prefix":"reports/"}}`
	snapshot := snapshotWithRoles(storage.IAMRole{
		RoleARN: roleARN,
		Statements: []storage.IAMPolicyStatement{
			conditional,
			allow(storage.IAMStatementOriginInline, "s3:PutObject"),
		},
	})

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0]
	assertStrings(t, result.Assigned, "s3:GetObject", "s3:PutObject")
	assertStrings(t, result.Unused, "s3:PutObject")
	assertStrings(t, result.Unresolved, "s3:GetObject")
	assertWarningContains(t, result.Warnings, "condition")
}

func TestEngineRunSortsAndDeduplicatesOutput(t *testing.T) {
	alphaARN := roleARN("Alpha")
	zuluARN := roleARN("Zulu")
	first := time.Now().UTC().Add(-2 * time.Hour)
	last := first.Add(time.Hour)
	store := &fakeUsageStore{usage: []storage.PermissionUsage{
		{RoleARN: zuluARN, IAMAction: "s3:PutObject", DeniedEvents: 1},
		{RoleARN: alphaARN, IAMAction: "S3:getobject", SuccessfulEvents: 2, FirstSuccess: first, LastSuccess: last},
		{RoleARN: alphaARN, IAMAction: "s3:GetObject", SuccessfulEvents: 3, FirstSuccess: first.Add(time.Minute), LastSuccess: last.Add(time.Minute)},
		{RoleARN: alphaARN, IAMAction: "ec2:DescribeInstances", FailedEvents: 1},
	}}
	snapshot := snapshotWithRoles(
		storage.IAMRole{RoleARN: zuluARN, Statements: []storage.IAMPolicyStatement{allow(storage.IAMStatementOriginManaged, "s3:PutObject")}},
		storage.IAMRole{RoleARN: alphaARN, Statements: []storage.IAMPolicyStatement{
			allow(storage.IAMStatementOriginInline, "s3:GetObject", "EC2:DescribeInstances", "S3:GETOBJECT"),
		}},
	)

	results, err := newTestEngine(store).Run(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].IAMRole != alphaARN || results[1].IAMRole != zuluARN {
		t.Fatalf("results not deterministically sorted: %#v", results)
	}
	alpha := results[0]
	assertStrings(t, alpha.Assigned, "EC2:DescribeInstances", "S3:GETOBJECT")
	if len(alpha.Usage) != 2 || alpha.Usage[0].Action != "ec2:DescribeInstances" || alpha.Usage[1].Action != "S3:getobject" {
		t.Fatalf("usage not sorted and deduplicated: %#v", alpha.Usage)
	}
	if alpha.Usage[1].SuccessfulEvents != 5 || !alpha.Usage[1].FirstSuccess.Equal(first) || !alpha.Usage[1].LastSuccess.Equal(last.Add(time.Minute)) {
		t.Fatalf("case-insensitive usage aggregates not merged: %#v", alpha.Usage[1])
	}
}

func TestEngineRunReturnsUsageQueryError(t *testing.T) {
	store := &fakeUsageStore{err: errors.New("clickhouse unavailable")}
	_, err := newTestEngine(store).Run(context.Background(), snapshotWithRoles())
	if err == nil || !strings.Contains(err.Error(), "querying permission usage") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestEngineRunReturnsCoverageQueryError(t *testing.T) {
	store := &fakeUsageStore{coverageErr: errors.New("clickhouse unavailable")}
	_, err := newTestEngine(store).Run(context.Background(), snapshotWithRoles())
	if err == nil || !strings.Contains(err.Error(), "querying collector coverage") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestClassifyPrivilege(t *testing.T) {
	tests := []struct {
		privilege string
		expected  RiskLevel
	}{
		{"s3:DeleteObject", RiskHigh},
		{"s3:GetObject", RiskLow},
		{"s3:PutObject", RiskMedium},
		{"s3:*", RiskHigh},
		{"s*:GetObject", RiskHigh},
		{"iam:PassRole", RiskHigh},
		{"iam:AttachRolePolicy", RiskHigh},
		{"iam:CreatePolicyVersion", RiskHigh},
		{"sts:AssumeRole", RiskHigh},
		{"iam:CreateRole", RiskMedium},
	}
	for _, test := range tests {
		t.Run(test.privilege, func(t *testing.T) {
			if got := ClassifyPrivilege(test.privilege); got != test.expected {
				t.Fatalf("ClassifyPrivilege(%q) = %q, want %q", test.privilege, got, test.expected)
			}
		})
	}
}

func TestClassifySet(t *testing.T) {
	if got := ClassifySet([]string{"s3:GetObject", "s3:PutObject"}); got != RiskMedium {
		t.Fatalf("ClassifySet() = %q, want MEDIUM", got)
	}
	if got := ClassifySet([]string{"s3:GetObject", "iam:PutRolePolicy"}); got != RiskHigh {
		t.Fatalf("ClassifySet() = %q, want HIGH", got)
	}
}

func TestMapSDKToIAM(t *testing.T) {
	if got := MapSDKToIAM("LAMBDA:invoke"); got != "lambda:InvokeFunction" {
		t.Fatalf("MapSDKToIAM() = %q", got)
	}
	if got := MapSDKToIAM("s3:GetObject"); got != "s3:GetObject" {
		t.Fatalf("MapSDKToIAM() changed canonical action to %q", got)
	}
}

func TestNormalizeRoleARN(t *testing.T) {
	assumed := "arn:aws-us-gov:sts::123456789012:assumed-role/team/DeployRole/build-123"
	want := "arn:aws-us-gov:iam::123456789012:role/team/DeployRole"
	if got := normalizeRoleARN(assumed); got != want {
		t.Fatalf("normalizeRoleARN(%q) = %q, want %q", assumed, got, want)
	}
}

func newTestEngine(store usageStore) *Engine {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := metrics.NewWithRegistry(prometheus.NewRegistry())
	return NewEngine(store, testTenant, testAccount, 30, 7, logger, m)
}

func snapshotWithRoles(roles ...storage.IAMRole) storage.IAMSnapshot {
	return storage.IAMSnapshot{
		SnapshotID:  "snapshot-1",
		AccountID:   testAccount,
		CollectedAt: time.Now().UTC(),
		Roles:       roles,
	}
}

func allow(origin string, actions ...string) storage.IAMPolicyStatement {
	return storage.IAMPolicyStatement{Origin: origin, Effect: "Allow", Actions: actions}
}

func roleARN(name string) string {
	return "arn:aws:iam::" + testAccount + ":role/" + name
}

func assertStrings(t *testing.T, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("strings = %#v, want %#v", got, want)
	}
}

func assertWarningContains(t *testing.T, warnings []string, want string) {
	t.Helper()
	for _, warning := range warnings {
		if strings.Contains(strings.ToLower(warning), strings.ToLower(want)) {
			return
		}
	}
	t.Fatalf("warnings %#v do not contain %q", warnings, want)
}
