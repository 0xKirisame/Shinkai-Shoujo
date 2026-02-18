package scraper

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// policyDocument represents an IAM policy document.
type policyDocument struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

// statement represents a single IAM policy statement.
type statement struct {
	Effect   string      `json:"Effect"`
	Action   ActionValue `json:"Action"`
	Resource interface{} `json:"Resource"`
}

// ActionValue handles both string and []string for the Action field.
type ActionValue []string

func (a *ActionValue) UnmarshalJSON(data []byte) error {
	// Try array first
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*a = arr
		return nil
	}
	// Try single string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("Action must be a string or array of strings: %w", err)
	}
	*a = ActionValue{s}
	return nil
}

// parsePolicyDocument decodes an IAM policy document from its URL-encoded JSON form.
// The policy document returned by GetPolicyVersion is URL-percent-encoded.
func parsePolicyDocument(encoded string) ([]string, error) {
	// URL-decode the document
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, fmt.Errorf("url-decoding policy: %w", err)
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil, fmt.Errorf("parsing policy JSON: %w", err)
	}

	// First pass: collect all explicitly Denied actions into a set (normalized).
	denied := make(map[string]struct{})
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Deny") {
			continue
		}
		for _, action := range stmt.Action {
			denied[normalizeAction(action)] = struct{}{}
		}
	}

	// Second pass: collect Allow actions, skipping those covered by the deny set.
	// Deny coverage rules applied here:
	//   - Exact match:       "s3:GetObject" denied if present in denied set.
	//   - Global wildcard:   "*" in denied set → everything is denied.
	//   - Service wildcard:  "s3:*" in denied set → all "s3:X" allowed actions are denied.
	// Note: denying a specific action does not "split" an allowed wildcard (e.g.
	// Allow "s3:*" + Deny "s3:DeleteObject" keeps "s3:*" in the result because we
	// cannot enumerate all S3 actions here). This edge case is intentionally accepted.
	seen := make(map[string]struct{})
	var actions []string
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		for _, action := range stmt.Action {
			norm := normalizeAction(action)
			if isDenied(norm, denied) {
				continue
			}
			key := strings.ToLower(norm)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				actions = append(actions, norm)
			}
		}
	}
	return actions, nil
}

// isDenied reports whether the (already-normalized) action is covered by the deny set.
func isDenied(action string, denied map[string]struct{}) bool {
	// Global wildcard: "*" in Deny → every action is denied.
	if _, ok := denied["*"]; ok {
		return true
	}
	// Exact match.
	if _, ok := denied[action]; ok {
		return true
	}
	// Service wildcard: "s3:*" in Deny → all "s3:X" actions are denied.
	if idx := strings.Index(action, ":"); idx != -1 {
		serviceWildcard := action[:idx+1] + "*"
		if _, ok := denied[serviceWildcard]; ok {
			return true
		}
	}
	return false
}

// normalizeAction lowercases the service prefix (before ':') and preserves action casing.
// e.g. "S3:GetObject" → "s3:GetObject", "s3:*" → "s3:*"
func normalizeAction(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0]) + ":" + parts[1]
	}
	// "*" or other bare wildcards
	return strings.ToLower(action)
}
