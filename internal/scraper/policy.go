package scraper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// policyDocument represents a decoded IAM policy document.
type policyDocument struct {
	Version   string
	Statement StatementValue
	Raw       string
}

// statement preserves the IAM statement fields used by a snapshot.
type statement struct {
	SID            string
	Effect         string
	Action         ActionValue
	NotAction      ActionValue
	Resource       StringValue
	NotResource    StringValue
	ConditionJSON  string
	hasAction      bool
	hasNotAction   bool
	hasResource    bool
	hasNotResource bool
}

// StatementValue handles both an object and an array for the Statement field.
type StatementValue []statement

func (s *StatementValue) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("Statement must be an object or array")
	}

	switch data[0] {
	case '{':
		stmt, err := parseStatement(data)
		if err != nil {
			return err
		}
		*s = StatementValue{stmt}
	case '[':
		var rawStatements []json.RawMessage
		if err := json.Unmarshal(data, &rawStatements); err != nil {
			return fmt.Errorf("Statement must be an array of objects: %w", err)
		}
		statements := make([]statement, 0, len(rawStatements))
		for i, raw := range rawStatements {
			stmt, err := parseStatement(raw)
			if err != nil {
				return fmt.Errorf("statement %d: %w", i, err)
			}
			statements = append(statements, stmt)
		}
		*s = statements
	default:
		return fmt.Errorf("Statement must be an object or array")
	}
	return nil
}

// StringValue handles the string-or-array shape used by IAM policy fields.
type StringValue []string

func (v *StringValue) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("value must be a string or array of strings")
	}

	switch data[0] {
	case '[':
		var values []string
		if err := json.Unmarshal(data, &values); err != nil {
			return fmt.Errorf("value must be an array of strings: %w", err)
		}
		if len(values) == 0 {
			return fmt.Errorf("value must not be an empty array")
		}
		for _, value := range values {
			if value == "" {
				return fmt.Errorf("value must not contain an empty string")
			}
		}
		*v = values
		return nil
	case '"':
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return fmt.Errorf("value must be a string: %w", err)
		}
		if value == "" {
			return fmt.Errorf("value must not be empty")
		}
		*v = StringValue{value}
		return nil
	default:
		return fmt.Errorf("value must be a string or array of strings")
	}
}

// ActionValue is retained for compatibility with existing parser callers.
type ActionValue = StringValue

func parseStatement(data []byte) (statement, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return statement{}, fmt.Errorf("statement must be an object: %w", err)
	}
	if fields == nil {
		return statement{}, fmt.Errorf("statement must be an object")
	}

	var stmt statement
	if raw, ok := fields["Sid"]; ok {
		if err := json.Unmarshal(raw, &stmt.SID); err != nil {
			return statement{}, fmt.Errorf("Sid must be a string: %w", err)
		}
	}
	rawEffect, ok := fields["Effect"]
	if !ok {
		return statement{}, fmt.Errorf("statement has no Effect")
	}
	if err := json.Unmarshal(rawEffect, &stmt.Effect); err != nil {
		return statement{}, fmt.Errorf("Effect must be a string: %w", err)
	}
	if stmt.Effect != "Allow" && stmt.Effect != "Deny" {
		return statement{}, fmt.Errorf("Effect must be Allow or Deny")
	}

	if raw, ok := fields["Action"]; ok {
		stmt.hasAction = true
		if err := json.Unmarshal(raw, &stmt.Action); err != nil {
			return statement{}, fmt.Errorf("Action: %w", err)
		}
	}
	if raw, ok := fields["NotAction"]; ok {
		stmt.hasNotAction = true
		if err := json.Unmarshal(raw, &stmt.NotAction); err != nil {
			return statement{}, fmt.Errorf("NotAction: %w", err)
		}
	}
	if stmt.hasAction == stmt.hasNotAction {
		return statement{}, fmt.Errorf("statement must contain exactly one of Action or NotAction")
	}

	if raw, ok := fields["Resource"]; ok {
		stmt.hasResource = true
		if err := json.Unmarshal(raw, &stmt.Resource); err != nil {
			return statement{}, fmt.Errorf("Resource: %w", err)
		}
	}
	if raw, ok := fields["NotResource"]; ok {
		stmt.hasNotResource = true
		if err := json.Unmarshal(raw, &stmt.NotResource); err != nil {
			return statement{}, fmt.Errorf("NotResource: %w", err)
		}
	}
	if stmt.hasResource == stmt.hasNotResource {
		return statement{}, fmt.Errorf("statement must contain exactly one of Resource or NotResource")
	}

	if raw, ok := fields["Condition"]; ok {
		condition, err := canonicalJSONObject(raw)
		if err != nil {
			return statement{}, fmt.Errorf("Condition: %w", err)
		}
		stmt.ConditionJSON = condition
	}
	return stmt, nil
}

func canonicalJSONObject(data []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value map[string]interface{}
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("must be an object: %w", err)
	}
	if value == nil {
		return "", fmt.Errorf("must be an object")
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("canonicalizing JSON: %w", err)
	}
	return string(canonical), nil
}

func parseFullPolicyDocument(encoded string) (policyDocument, error) {
	decoded := encoded
	if !json.Valid([]byte(decoded)) {
		pathDecoded, pathErr := url.PathUnescape(encoded)
		if pathErr == nil && json.Valid([]byte(pathDecoded)) {
			decoded = pathDecoded
		} else {
			var err error
			decoded, err = url.QueryUnescape(encoded)
			if err != nil {
				return policyDocument{}, fmt.Errorf("url-decoding policy: %w", err)
			}
		}
	}

	var raw struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(decoded), &raw); err != nil {
		return policyDocument{}, fmt.Errorf("parsing policy JSON: %w", err)
	}
	if len(raw.Statement) == 0 {
		return policyDocument{}, fmt.Errorf("policy has no Statement")
	}
	var statements StatementValue
	if err := json.Unmarshal(raw.Statement, &statements); err != nil {
		return policyDocument{}, fmt.Errorf("parsing policy Statement: %w", err)
	}
	return policyDocument{Version: raw.Version, Statement: statements, Raw: decoded}, nil
}

// parsePolicyDocument returns the flattened Allow/Action inventory used by
// correlation. Full snapshot scraping uses parseFullPolicyDocument instead.
func parsePolicyDocument(encoded string) ([]string, error) {
	doc, err := parseFullPolicyDocument(encoded)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var actions []string
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if stmt.hasNotAction {
			return nil, fmt.Errorf("Allow statement using NotAction cannot be represented safely")
		}
		for _, action := range stmt.Action {
			normalized := normalizeAction(action)
			key := strings.ToLower(normalized)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			actions = append(actions, normalized)
		}
	}
	return actions, nil
}

// normalizeAction lowercases the service prefix (before ':') and preserves action casing.
func normalizeAction(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		return strings.ToLower(parts[0]) + ":" + parts[1]
	}
	return strings.ToLower(action)
}
