package correlation

import "strings"

// RiskLevel represents the risk classification for an IAM privilege.
type RiskLevel string

const (
	RiskHigh   RiskLevel = "HIGH"
	RiskMedium RiskLevel = "MEDIUM"
	RiskLow    RiskLevel = "LOW"
)

// highPrefixes are action prefixes that indicate high-risk operations.
var highPrefixes = []string{"Delete", "Terminate"}

// highActions are well-known privilege-escalation operations whose names do
// not otherwise look destructive.
var highActions = map[string]struct{}{
	"iam:addusertogroup":          {},
	"iam:attachgrouppolicy":       {},
	"iam:attachrolepolicy":        {},
	"iam:attachuserpolicy":        {},
	"iam:createaccesskey":         {},
	"iam:createloginprofile":      {},
	"iam:createpolicyversion":     {},
	"iam:passrole":                {},
	"iam:putgrouppolicy":          {},
	"iam:putrolepolicy":           {},
	"iam:putuserpolicy":           {},
	"iam:setdefaultpolicyversion": {},
	"iam:updateassumerolepolicy":  {},
	"iam:updateloginprofile":      {},
	"sts:assumerole":              {},
}

// lowPrefixes are action prefixes that indicate low-risk (read-only) operations.
var lowPrefixes = []string{"Describe", "List", "Get"}

// mediumPrefixes are action prefixes that indicate medium-risk operations.
var mediumPrefixes = []string{"Create", "Put", "Modify", "Update", "Attach", "Detach"}

// ClassifyPrivilege returns the risk level for a single IAM privilege.
// Format: "service:Action" or "service:*" or "*".
func ClassifyPrivilege(privilege string) RiskLevel {
	if strings.ContainsAny(privilege, "*?") {
		return RiskHigh
	}

	parts := strings.SplitN(privilege, ":", 2)
	var action string
	if len(parts) == 2 {
		action = parts[1]
	} else {
		action = privilege
	}

	privilegeLower := strings.ToLower(privilege)
	actionLower := strings.ToLower(action)
	if _, high := highActions[privilegeLower]; high {
		return RiskHigh
	}

	for _, prefix := range highPrefixes {
		if strings.HasPrefix(actionLower, strings.ToLower(prefix)) {
			return RiskHigh
		}
	}
	for _, prefix := range lowPrefixes {
		if strings.HasPrefix(actionLower, strings.ToLower(prefix)) {
			return RiskLow
		}
	}
	for _, prefix := range mediumPrefixes {
		if strings.HasPrefix(actionLower, strings.ToLower(prefix)) {
			return RiskMedium
		}
	}

	// Default for unknown patterns
	return RiskMedium
}

// ClassifySet returns the highest risk level across a set of privileges.
// If the set is empty, returns LOW.
func ClassifySet(privileges []string) RiskLevel {
	if len(privileges) == 0 {
		return RiskLow
	}
	highest := RiskLow
	for _, p := range privileges {
		level := ClassifyPrivilege(p)
		if level == RiskHigh {
			return RiskHigh // short-circuit
		}
		if level == RiskMedium {
			highest = RiskMedium
		}
	}
	return highest
}
