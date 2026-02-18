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

	seen := make(map[string]struct{})
	var actions []string
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		for _, action := range stmt.Action {
			key := strings.ToLower(action)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				// Preserve original casing for the action name part, lowercase service prefix
				actions = append(actions, normalizeAction(action))
			}
		}
	}
	return actions, nil
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
