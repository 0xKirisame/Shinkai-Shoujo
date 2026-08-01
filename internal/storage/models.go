package storage

import "time"

const (
	IAMStatementOriginManaged  = "managed"
	IAMStatementOriginInline   = "inline"
	IAMStatementOriginBoundary = "boundary"
)

// UsageEvent is one observed AWS API usage event.
type UsageEvent struct {
	EventID      string
	EventTime    time.Time
	ReceivedAt   time.Time
	TenantID     string
	AccountID    string
	RoleARN      string
	Workload     string
	Environment  string
	AWSService   string
	SDKOperation string
	IAMAction    string
	Outcome      string
	RequestID    string
	TraceID      string
	SpanID       string
}

// UsageQuery filters permission usage. Zero times and empty strings do not
// constrain their corresponding fields. Until is an exclusive upper bound.
type UsageQuery struct {
	TenantID    string
	AccountID   string
	RoleARN     string
	Workload    string
	Environment string
	Since       time.Time
	Until       time.Time
}

// PermissionUsage aggregates unique usage events for one role and IAM action.
type PermissionUsage struct {
	RoleARN          string
	IAMAction        string
	SuccessfulEvents uint64
	DeniedEvents     uint64
	FailedEvents     uint64
	FirstSuccess     time.Time
	LastSuccess      time.Time
}

// CollectorCoverage summarizes collector heartbeats in a time window.
type CollectorCoverage struct {
	FirstHeartbeat time.Time
	LastHeartbeat  time.Time
	Received       uint64
	Accepted       uint64
}

// IAMSnapshot is a complete point-in-time view of an account's IAM roles.
type IAMSnapshot struct {
	SnapshotID  string
	AccountID   string
	CollectedAt time.Time
	Roles       []IAMRole
}

// IAMRole preserves role identity and its policy statements.
type IAMRole struct {
	RoleARN    string
	RoleName   string
	RoleID     string
	Path       string
	Statements []IAMPolicyStatement
}

// IAMPolicyStatement preserves policy provenance and IAM's raw statement
// semantics. Origin is managed, inline, or boundary.
type IAMPolicyStatement struct {
	Origin          string
	PolicyARN       string
	PolicyName      string
	PolicyVersionID string
	StatementID     string
	Effect          string
	Actions         []string
	NotActions      []string
	Resources       []string
	NotResources    []string
	ConditionJSON   string
	RawDocument     string
}
