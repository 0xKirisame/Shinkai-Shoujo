package scraper

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
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
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListPolicyVersions(ctx context.Context, params *iam.ListPolicyVersionsInput, optFns ...func(*iam.Options)) (*iam.ListPolicyVersionsOutput, error)
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
	for res := range resultCh {
		if res.err != nil {
			s.log.Warn("failed to scrape role, skipping", "error", res.err)
			continue
		}
		assignments = append(assignments, res.ra)
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
			s.log.Warn("failed to get policy actions, skipping policy",
				"role", roleName, "policy", policyARN, "error", err)
			continue
		}
		for _, action := range actions {
			if _, ok := seen[action]; !ok {
				seen[action] = struct{}{}
				ra.Privileges = append(ra.Privileges, action)
			}
		}
	}

	// Collect inline (embedded) role policies using the same seen map to deduplicate.
	inlineNames, err := s.listInlinePolicies(ctx, roleName)
	if err != nil {
		s.log.Warn("failed to list inline policies, skipping", "role", roleName, "error", err)
	} else {
		for _, policyName := range inlineNames {
			out, err := s.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				s.log.Warn("failed to get inline policy, skipping",
					"role", roleName, "policy", policyName, "error", err)
				continue
			}
			actions, err := parsePolicyDocument(aws.ToString(out.PolicyDocument))
			if err != nil {
				s.log.Warn("failed to parse inline policy document, skipping",
					"role", roleName, "policy", policyName, "error", err)
				continue
			}
			for _, action := range actions {
				if _, ok := seen[action]; !ok {
					seen[action] = struct{}{}
					ra.Privileges = append(ra.Privileges, action)
				}
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
	// Find the default (active) version of the policy.
	versionsOut, err := s.client.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{
		PolicyArn: aws.String(policyARN),
	})
	if err != nil {
		return nil, fmt.Errorf("listing policy versions: %w", err)
	}

	var defaultVersionID string
	for _, v := range versionsOut.Versions {
		if v.IsDefaultVersion {
			defaultVersionID = aws.ToString(v.VersionId)
			break
		}
	}
	if defaultVersionID == "" {
		return nil, fmt.Errorf("no default version found for policy %s", policyARN)
	}

	versionOut, err := s.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: aws.String(defaultVersionID),
	})
	if err != nil {
		return nil, fmt.Errorf("getting policy version: %w", err)
	}

	doc := aws.ToString(versionOut.PolicyVersion.Document)
	if doc == "" {
		return nil, nil
	}

	return parsePolicyDocument(doc)
}
