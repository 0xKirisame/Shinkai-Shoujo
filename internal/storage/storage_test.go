package storage

import (
	"context"
	"testing"
	"time"
)

func TestOpenMemory(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory() error: %v", err)
	}
	defer db.Close()
}

func TestBatchRecordAndQuery(t *testing.T) {
	ctx := context.Background()
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	records := []PrivilegeUsageRecord{
		{Timestamp: now, IAMRole: "arn:aws:iam::123:role/MyRole", Privilege: "s3:GetObject", CallCount: 5},
		{Timestamp: now, IAMRole: "arn:aws:iam::123:role/MyRole", Privilege: "s3:PutObject", CallCount: 2},
		{Timestamp: now, IAMRole: "arn:aws:iam::123:role/OtherRole", Privilege: "ec2:DescribeInstances", CallCount: 1},
	}

	if err := db.BatchRecordPrivilegeUsage(ctx, records); err != nil {
		t.Fatalf("BatchRecordPrivilegeUsage() error: %v", err)
	}

	since := now.Add(-time.Hour)
	privs, err := db.GetUsedPrivilegesForRole(ctx, "arn:aws:iam::123:role/MyRole", since)
	if err != nil {
		t.Fatalf("GetUsedPrivilegesForRole() error: %v", err)
	}
	if len(privs) != 2 {
		t.Errorf("expected 2 privileges, got %d: %v", len(privs), privs)
	}
}

func TestGetObservedRoles(t *testing.T) {
	ctx := context.Background()
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	records := []PrivilegeUsageRecord{
		{Timestamp: now, IAMRole: "role/A", Privilege: "s3:GetObject", CallCount: 1},
		{Timestamp: now, IAMRole: "role/B", Privilege: "s3:PutObject", CallCount: 1},
		{Timestamp: now, IAMRole: "role/A", Privilege: "ec2:Describe", CallCount: 1},
	}
	if err := db.BatchRecordPrivilegeUsage(ctx, records); err != nil {
		t.Fatal(err)
	}

	roles, err := db.GetObservedRoles(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

func TestSaveAndGetAnalysisResult(t *testing.T) {
	ctx := context.Background()
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	r := AnalysisResult{
		AnalysisDate:  time.Now(),
		IAMRole:       "role/Test",
		AssignedPrivs: []string{"s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"},
		UsedPrivs:     []string{"s3:GetObject"},
		UnusedPrivs:   []string{"s3:PutObject", "ec2:DescribeInstances"},
		RiskLevel:     "MEDIUM",
	}

	if err := db.SaveAnalysisResult(ctx, r); err != nil {
		t.Fatalf("SaveAnalysisResult() error: %v", err)
	}

	results, err := db.GetLatestAnalysisResults(ctx)
	if err != nil {
		t.Fatalf("GetLatestAnalysisResults() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].IAMRole != "role/Test" {
		t.Errorf("unexpected role: %s", results[0].IAMRole)
	}
	if len(results[0].UnusedPrivs) != 2 {
		t.Errorf("expected 2 unused, got %d", len(results[0].UnusedPrivs))
	}
}

func TestSaveAnalysisResultUpsert(t *testing.T) {
	ctx := context.Background()
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	role := "role/UpsertTest"

	first := AnalysisResult{
		AnalysisDate:  time.Now().Add(-time.Hour),
		IAMRole:       role,
		AssignedPrivs: []string{"s3:GetObject", "s3:PutObject"},
		UsedPrivs:     []string{"s3:GetObject"},
		UnusedPrivs:   []string{"s3:PutObject"},
		RiskLevel:     "LOW",
	}
	if err := db.SaveAnalysisResult(ctx, first); err != nil {
		t.Fatalf("first SaveAnalysisResult() error: %v", err)
	}

	second := AnalysisResult{
		AnalysisDate:  time.Now(),
		IAMRole:       role,
		AssignedPrivs: []string{"s3:GetObject"},
		UsedPrivs:     []string{"s3:GetObject"},
		UnusedPrivs:   []string{},
		RiskLevel:     "NONE",
	}
	if err := db.SaveAnalysisResult(ctx, second); err != nil {
		t.Fatalf("second SaveAnalysisResult() error: %v", err)
	}

	results, err := db.GetLatestAnalysisResults(ctx)
	if err != nil {
		t.Fatalf("GetLatestAnalysisResults() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 row after upsert, got %d", len(results))
	}
	if results[0].RiskLevel != "NONE" {
		t.Errorf("expected updated RiskLevel NONE, got %s", results[0].RiskLevel)
	}
}

func TestPurgeOldRecords(t *testing.T) {
	ctx := context.Background()
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	old := time.Now().Add(-48 * time.Hour)
	recent := time.Now()

	records := []PrivilegeUsageRecord{
		{Timestamp: old, IAMRole: "role/A", Privilege: "s3:GetObject", CallCount: 1},
		{Timestamp: recent, IAMRole: "role/A", Privilege: "s3:PutObject", CallCount: 1},
	}
	if err := db.BatchRecordPrivilegeUsage(ctx, records); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	n, err := db.PurgeOldRecords(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 purged record, got %d", n)
	}

	remaining, err := db.GetObservedRoles(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Errorf("expected 1 role remaining after purge, got %d", len(remaining))
	}
}
