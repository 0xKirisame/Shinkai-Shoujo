package scraper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// maxConcurrentRoleScrapes limits parallel IAM API calls to avoid throttling.
const maxConcurrentRoleScrapes = 5

// RoleAssignment associates an IAM role with its allowed privileges.
type RoleAssignment struct {
	RoleName string
	RoleARN  string
	// Privileges is the deduplicated set of allowed IAM actions.
	// Wildcards like "s3:*" or "*" are stored literally.
	Privileges []string
}

// iamClient is the subset of the AWS IAM client we use (for easy testing).
type iamClient interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
}

// Scraper fetches IAM role assignments.
type Scraper struct {
	client iamClient
	log    *slog.Logger
}

// New creates a Scraper with the given AWS config.
func New(cfg aws.Config, log *slog.Logger) *Scraper {
	return &Scraper{
		client: iam.NewFromConfig(cfg),
		log:    log,
	}
}

// ScrapeSnapshot returns a complete point-in-time view of all non-service-linked
// IAM roles. Any list, get, decode, or validation failure rejects the snapshot.
func (s *Scraper) ScrapeSnapshot(ctx context.Context, accountID string) (storage.IAMSnapshot, error) {
	allRoles, err := s.listAllRoles(ctx)
	if err != nil {
		return storage.IAMSnapshot{}, fmt.Errorf("listing roles: %w", err)
	}

	resolvedAccountID, err := resolveAccountID(accountID, allRoles)
	if err != nil {
		return storage.IAMSnapshot{}, err
	}

	roles := make([]types.Role, 0, len(allRoles))
	for _, role := range allRoles {
		if strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/") {
			continue
		}
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool {
		return aws.ToString(roles[i].Arn) < aws.ToString(roles[j].Arn)
	})

	type scrapeResult struct {
		role storage.IAMRole
		err  error
	}
	resultCh := make(chan scrapeResult, len(roles))
	sem := make(chan struct{}, maxConcurrentRoleScrapes)
	cache := newManagedPolicyCache()

	var wg sync.WaitGroup
	for _, role := range roles {
		role := role
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				resultCh <- scrapeResult{err: ctx.Err()}
				return
			}

			snapshotRole, err := s.scrapeSnapshotRole(ctx, role, cache)
			resultCh <- scrapeResult{role: snapshotRole, err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	snapshotRoles := make([]storage.IAMRole, 0, len(roles))
	var scrapeErrors []error
	for result := range resultCh {
		if result.err != nil {
			scrapeErrors = append(scrapeErrors, result.err)
			continue
		}
		snapshotRoles = append(snapshotRoles, result.role)
	}
	if len(scrapeErrors) > 0 {
		return storage.IAMSnapshot{}, fmt.Errorf("scraping IAM roles: %w", errors.Join(scrapeErrors...))
	}
	sort.Slice(snapshotRoles, func(i, j int) bool {
		return snapshotRoles[i].RoleARN < snapshotRoles[j].RoleARN
	})

	snapshotIDBytes := make([]byte, 16)
	if _, err := rand.Read(snapshotIDBytes); err != nil {
		return storage.IAMSnapshot{}, fmt.Errorf("generating snapshot ID: %w", err)
	}
	return storage.IAMSnapshot{
		SnapshotID:  hex.EncodeToString(snapshotIDBytes),
		AccountID:   resolvedAccountID,
		CollectedAt: time.Now().UTC(),
		Roles:       snapshotRoles,
	}, nil
}

func resolveAccountID(accountID string, roles []types.Role) (string, error) {
	resolved := accountID
	for _, role := range roles {
		roleARN := aws.ToString(role.Arn)
		parsed, err := arn.Parse(roleARN)
		if err != nil || parsed.Service != "iam" || parsed.AccountID == "" || !strings.HasPrefix(parsed.Resource, "role/") {
			if err != nil {
				return "", fmt.Errorf("role %q has invalid ARN: %w", aws.ToString(role.RoleName), err)
			}
			return "", fmt.Errorf("role %q has invalid IAM role ARN %q", aws.ToString(role.RoleName), roleARN)
		}
		if resolved == "" {
			resolved = parsed.AccountID
			continue
		}
		if parsed.AccountID != resolved {
			return "", fmt.Errorf("role %q ARN account %q does not match account %q", aws.ToString(role.RoleName), parsed.AccountID, resolved)
		}
	}
	if resolved == "" {
		return "", fmt.Errorf("cannot derive account ID without IAM role ARNs")
	}
	return resolved, nil
}

func (s *Scraper) scrapeSnapshotRole(ctx context.Context, role types.Role, cache *managedPolicyCache) (storage.IAMRole, error) {
	roleName := aws.ToString(role.RoleName)
	snapshotRole := storage.IAMRole{
		RoleARN:  aws.ToString(role.Arn),
		RoleName: roleName,
		RoleID:   aws.ToString(role.RoleId),
		Path:     aws.ToString(role.Path),
	}
	if roleName == "" {
		return storage.IAMRole{}, fmt.Errorf("role %q has no name", snapshotRole.RoleARN)
	}

	attached, err := s.listAttachedPolicies(ctx, roleName)
	if err != nil {
		return storage.IAMRole{}, fmt.Errorf("role %s: listing attached policies: %w", roleName, err)
	}
	sort.Slice(attached, func(i, j int) bool {
		leftARN, rightARN := aws.ToString(attached[i].PolicyArn), aws.ToString(attached[j].PolicyArn)
		if leftARN == rightARN {
			return aws.ToString(attached[i].PolicyName) < aws.ToString(attached[j].PolicyName)
		}
		return leftARN < rightARN
	})
	for _, attachedPolicy := range attached {
		policyARN := aws.ToString(attachedPolicy.PolicyArn)
		if policyARN == "" {
			return storage.IAMRole{}, fmt.Errorf("role %s: attached policy has no ARN", roleName)
		}
		managed, err := s.getManagedPolicy(ctx, policyARN, cache)
		if err != nil {
			return storage.IAMRole{}, fmt.Errorf("role %s: managed policy %s: %w", roleName, policyARN, err)
		}
		policyName := aws.ToString(attachedPolicy.PolicyName)
		if policyName == "" {
			policyName = managed.name
		}
		if policyName == "" {
			return storage.IAMRole{}, fmt.Errorf("role %s: managed policy %s has no name", roleName, policyARN)
		}
		snapshotRole.Statements = append(snapshotRole.Statements, policyStatements(
			managed.document, storage.IAMStatementOriginManaged, policyARN, policyName, managed.versionID,
		)...)
	}

	inlineNames, err := s.listInlinePolicies(ctx, roleName)
	if err != nil {
		return storage.IAMRole{}, fmt.Errorf("role %s: listing inline policies: %w", roleName, err)
	}
	sort.Strings(inlineNames)
	for _, policyName := range inlineNames {
		if policyName == "" {
			return storage.IAMRole{}, fmt.Errorf("role %s: inline policy has no name", roleName)
		}
		out, err := s.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			return storage.IAMRole{}, fmt.Errorf("role %s: getting inline policy %s: %w", roleName, policyName, err)
		}
		if out == nil || out.PolicyDocument == nil {
			return storage.IAMRole{}, fmt.Errorf("role %s: inline policy %s has no document", roleName, policyName)
		}
		document, err := parseFullPolicyDocument(aws.ToString(out.PolicyDocument))
		if err != nil {
			return storage.IAMRole{}, fmt.Errorf("role %s: parsing inline policy %s: %w", roleName, policyName, err)
		}
		snapshotRole.Statements = append(snapshotRole.Statements, policyStatements(
			document, storage.IAMStatementOriginInline, "", policyName, "",
		)...)
	}

	if role.PermissionsBoundary != nil {
		policyARN := aws.ToString(role.PermissionsBoundary.PermissionsBoundaryArn)
		if policyARN == "" {
			return storage.IAMRole{}, fmt.Errorf("role %s: permissions boundary has no ARN", roleName)
		}
		managed, err := s.getManagedPolicy(ctx, policyARN, cache)
		if err != nil {
			return storage.IAMRole{}, fmt.Errorf("role %s: permissions boundary %s: %w", roleName, policyARN, err)
		}
		if managed.name == "" {
			return storage.IAMRole{}, fmt.Errorf("role %s: permissions boundary %s has no name", roleName, policyARN)
		}
		snapshotRole.Statements = append(snapshotRole.Statements, policyStatements(
			managed.document, storage.IAMStatementOriginBoundary, policyARN, managed.name, managed.versionID,
		)...)
	}
	return snapshotRole, nil
}

func policyStatements(document policyDocument, origin, policyARN, policyName, versionID string) []storage.IAMPolicyStatement {
	statements := make([]storage.IAMPolicyStatement, 0, len(document.Statement))
	for _, parsed := range document.Statement {
		statements = append(statements, storage.IAMPolicyStatement{
			Origin:          origin,
			PolicyARN:       policyARN,
			PolicyName:      policyName,
			PolicyVersionID: versionID,
			StatementID:     parsed.SID,
			Effect:          parsed.Effect,
			Actions:         append([]string(nil), parsed.Action...),
			NotActions:      append([]string(nil), parsed.NotAction...),
			Resources:       append([]string(nil), parsed.Resource...),
			NotResources:    append([]string(nil), parsed.NotResource...),
			ConditionJSON:   parsed.ConditionJSON,
			RawDocument:     document.Raw,
		})
	}
	return statements
}

// ScrapeAll fetches all customer-managed roles and their privileges concurrently.
// Service-linked roles (path prefix /aws-service-role/) are skipped — they are
// managed by AWS and cannot be modified.
// Both attached managed policies and inline role policies are collected.
func (s *Scraper) ScrapeAll(ctx context.Context) ([]RoleAssignment, error) {
	allRoles, err := s.listAllRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	// Filter out service-linked roles.
	roles := allRoles[:0]
	for _, r := range allRoles {
		if strings.HasPrefix(aws.ToString(r.Path), "/aws-service-role/") {
			s.log.Debug("skipping service-linked role", "role", aws.ToString(r.RoleName))
			continue
		}
		roles = append(roles, r)
	}

	s.log.Info("scraping IAM roles", "total", len(allRoles), "customer_managed", len(roles))

	type scrapeResult struct {
		ra  RoleAssignment
		err error
	}

	resultCh := make(chan scrapeResult, len(roles))
	sem := make(chan struct{}, maxConcurrentRoleScrapes)

	var wg sync.WaitGroup
	for _, role := range roles {
		role := role // capture loop variable
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			ra, err := s.ScrapeRole(ctx, role)
			resultCh <- scrapeResult{ra, err}
		}()
	}

	// Close channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	assignments := make([]RoleAssignment, 0, len(roles))
	var scrapeErrors []error
	for res := range resultCh {
		if res.err != nil {
			scrapeErrors = append(scrapeErrors, res.err)
			continue
		}
		assignments = append(assignments, res.ra)
	}
	if len(scrapeErrors) > 0 {
		return nil, fmt.Errorf("scraping IAM roles: %w", errors.Join(scrapeErrors...))
	}
	return assignments, nil
}

// ScrapeRole fetches the attached policies for a single role and returns its assignment.
func (s *Scraper) ScrapeRole(ctx context.Context, role types.Role) (RoleAssignment, error) {
	roleName := aws.ToString(role.RoleName)
	ra := RoleAssignment{
		RoleName: roleName,
		RoleARN:  aws.ToString(role.Arn),
	}

	policies, err := s.listAttachedPolicies(ctx, roleName)
	if err != nil {
		return ra, fmt.Errorf("role %s: listing attached policies: %w", roleName, err)
	}

	seen := make(map[string]struct{})
	for _, policy := range policies {
		policyARN := aws.ToString(policy.PolicyArn)
		actions, err := s.getPolicyActions(ctx, policyARN)
		if err != nil {
			return ra, fmt.Errorf("role %s: managed policy %s: %w", roleName, policyARN, err)
		}
		for _, action := range actions {
			key := strings.ToLower(action)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				ra.Privileges = append(ra.Privileges, action)
			}
		}
	}

	// Collect inline (embedded) role policies using the same seen map to deduplicate.
	inlineNames, err := s.listInlinePolicies(ctx, roleName)
	if err != nil {
		return ra, fmt.Errorf("role %s: listing inline policies: %w", roleName, err)
	}
	for _, policyName := range inlineNames {
		out, err := s.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			return ra, fmt.Errorf("role %s: getting inline policy %s: %w", roleName, policyName, err)
		}
		if out == nil || out.PolicyDocument == nil {
			return ra, fmt.Errorf("role %s: inline policy %s has no document", roleName, policyName)
		}
		actions, err := parsePolicyDocument(aws.ToString(out.PolicyDocument))
		if err != nil {
			return ra, fmt.Errorf("role %s: parsing inline policy %s: %w", roleName, policyName, err)
		}
		for _, action := range actions {
			key := strings.ToLower(action)
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				ra.Privileges = append(ra.Privileges, action)
			}
		}
	}

	return ra, nil
}

// listInlinePolicies returns the names of all inline policies attached to a role.
func (s *Scraper) listInlinePolicies(ctx context.Context, roleName string) ([]string, error) {
	var names []string
	paginator := iam.NewListRolePoliciesPaginator(s.client, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		names = append(names, page.PolicyNames...)
	}
	return names, nil
}

func (s *Scraper) listAllRoles(ctx context.Context) ([]types.Role, error) {
	var roles []types.Role
	paginator := iam.NewListRolesPaginator(s.client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		roles = append(roles, page.Roles...)
	}
	return roles, nil
}

func (s *Scraper) listAttachedPolicies(ctx context.Context, roleName string) ([]types.AttachedPolicy, error) {
	var policies []types.AttachedPolicy
	paginator := iam.NewListAttachedRolePoliciesPaginator(s.client, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		policies = append(policies, page.AttachedPolicies...)
	}
	return policies, nil
}

func (s *Scraper) getPolicyActions(ctx context.Context, policyARN string) ([]string, error) {
	policyOut, err := s.client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(policyARN),
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy: %w", err)
	}
	if policyOut == nil || policyOut.Policy == nil {
		return nil, fmt.Errorf("policy %s has no metadata", policyARN)
	}
	defaultVersionID := aws.ToString(policyOut.Policy.DefaultVersionId)
	if defaultVersionID == "" {
		return nil, fmt.Errorf("policy %s has no default version", policyARN)
	}

	versionOut, err := s.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: aws.String(defaultVersionID),
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy version: %w", err)
	}
	if versionOut == nil || versionOut.PolicyVersion == nil {
		return nil, fmt.Errorf("policy %s version %s has no metadata", policyARN, defaultVersionID)
	}
	doc := aws.ToString(versionOut.PolicyVersion.Document)
	if doc == "" {
		return nil, fmt.Errorf("policy %s version %s has no document", policyARN, defaultVersionID)
	}

	actions, err := parsePolicyDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("parsing policy version: %w", err)
	}
	return actions, nil
}

type managedPolicy struct {
	name      string
	versionID string
	document  policyDocument
}

type managedPolicyMetadata struct {
	name      string
	versionID string
}

type metadataCall struct {
	done     chan struct{}
	metadata managedPolicyMetadata
	err      error
}

type documentCall struct {
	done     chan struct{}
	document policyDocument
	err      error
}

type managedPolicyCache struct {
	mu        sync.Mutex
	metadata  map[string]*metadataCall
	documents map[string]*documentCall
}

func newManagedPolicyCache() *managedPolicyCache {
	return &managedPolicyCache{
		metadata:  make(map[string]*metadataCall),
		documents: make(map[string]*documentCall),
	}
}

func (s *Scraper) getManagedPolicy(ctx context.Context, policyARN string, cache *managedPolicyCache) (managedPolicy, error) {
	metadata, err := s.getManagedPolicyMetadata(ctx, policyARN, cache)
	if err != nil {
		return managedPolicy{}, err
	}
	document, err := s.getManagedPolicyDocument(ctx, policyARN, metadata.versionID, cache)
	if err != nil {
		return managedPolicy{}, err
	}
	return managedPolicy{name: metadata.name, versionID: metadata.versionID, document: document}, nil
}

func (s *Scraper) getManagedPolicyMetadata(ctx context.Context, policyARN string, cache *managedPolicyCache) (managedPolicyMetadata, error) {
	cache.mu.Lock()
	if call, ok := cache.metadata[policyARN]; ok {
		cache.mu.Unlock()
		select {
		case <-call.done:
			return call.metadata, call.err
		case <-ctx.Done():
			return managedPolicyMetadata{}, ctx.Err()
		}
	}
	call := &metadataCall{done: make(chan struct{})}
	cache.metadata[policyARN] = call
	cache.mu.Unlock()

	out, err := s.client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(policyARN)})
	if err != nil {
		call.err = fmt.Errorf("getting policy: %w", err)
	} else if out == nil || out.Policy == nil {
		call.err = fmt.Errorf("policy %s has no metadata", policyARN)
	} else {
		call.metadata = managedPolicyMetadata{
			name:      aws.ToString(out.Policy.PolicyName),
			versionID: aws.ToString(out.Policy.DefaultVersionId),
		}
		if call.metadata.versionID == "" {
			call.err = fmt.Errorf("policy %s has no default version", policyARN)
		}
	}

	cache.mu.Lock()
	close(call.done)
	cache.mu.Unlock()
	return call.metadata, call.err
}

func (s *Scraper) getManagedPolicyDocument(ctx context.Context, policyARN, versionID string, cache *managedPolicyCache) (policyDocument, error) {
	key := policyARN + "\x00" + versionID
	cache.mu.Lock()
	if call, ok := cache.documents[key]; ok {
		cache.mu.Unlock()
		select {
		case <-call.done:
			return call.document, call.err
		case <-ctx.Done():
			return policyDocument{}, ctx.Err()
		}
	}
	call := &documentCall{done: make(chan struct{})}
	cache.documents[key] = call
	cache.mu.Unlock()

	out, err := s.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		call.err = fmt.Errorf("getting policy version: %w", err)
	} else if out == nil || out.PolicyVersion == nil {
		call.err = fmt.Errorf("policy %s version %s has no metadata", policyARN, versionID)
	} else if out.PolicyVersion.Document == nil || aws.ToString(out.PolicyVersion.Document) == "" {
		call.err = fmt.Errorf("policy %s version %s has no document", policyARN, versionID)
	} else {
		call.document, call.err = parseFullPolicyDocument(aws.ToString(out.PolicyVersion.Document))
		if call.err != nil {
			call.err = fmt.Errorf("parsing policy version: %w", call.err)
		}
	}

	cache.mu.Lock()
	close(call.done)
	cache.mu.Unlock()
	return call.document, call.err
}
