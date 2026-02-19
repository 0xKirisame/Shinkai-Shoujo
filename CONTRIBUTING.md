# Contributing to Shinkai Shoujo

Thanks for your interest in contributing! Shinkai Shoujo aims to be the simplest, most maintainable CIEM tool possible. We value **simplicity over features** and **standard tools over custom solutions**.

---

## Philosophy

Before contributing, please understand our core principles:

1. **KISS (Keep It Simple, Stupid)**
   - Favor boring solutions over clever ones
   - Remove code before adding code
   - Say no to features that add complexity

2. **Use Standard Tools**
   - OpenTelemetry (not custom telemetry)
   - Grafana (not custom dashboards)
   - Terraform (not proprietary DSL)
   - SQLite (not complex databases)

3. **Maintainability > Features**
   - Every line of code is a liability
   - If you can't maintain it yourself, don't add it
   - Documentation is part of the feature

4. **Agentless Forever**
   - Never require agent deployment
   - Never add kernel dependencies
   - Keep it deployable in 5 minutes

---

## How to Contribute

### 🐛 Bug Reports

**Before opening an issue:**
1. Check existing issues (including closed ones)
2. Try the latest version
3. Read the troubleshooting guide

**When reporting:**
```markdown
**Environment:**
- Shinkai version: `shinkai-shoujo version`
- Go version: `go version`
- OS: `uname -a`
- OTel Collector version: (if relevant)

**Steps to reproduce:**
1. Configure with...
2. Run `shinkai-shoujo analyze`
3. See error...

**Expected behavior:**
What should happen

**Actual behavior:**
What actually happens

**Logs:**
```
[paste relevant logs]
```

**Config:**
```yaml
[paste sanitized config.yaml]
```
```

---

### 💡 Feature Requests

**We're very conservative about adding features.**

Before proposing a feature, ask yourself:
- Does this solve a problem for >50% of users?
- Can this be done with existing tools (Grafana plugins, Terraform modules)?
- Does this add significant complexity?
- Can we remove something else to make room?

**Good feature requests:**
- Support for GCP IAM (major cloud provider)
- CloudTrail fallback (increases accuracy)
- Scheduled job auto-detection (common use case)

**Bad feature requests:**
- Custom web UI (use Grafana)
- Real-time streaming (batch is fine)
- ML-based anomaly detection (complexity)
- Custom alerting (use Grafana alerts)

**Format:**
```markdown
**Problem:**
Clear description of the problem you're trying to solve

**Proposed solution:**
How you think it should work

**Alternatives considered:**
Other ways to solve this (including existing tools)

**Impact:**
How many users would benefit?
```

---

### 🔧 Pull Requests

**Before writing code:**
1. Open an issue to discuss the change
2. Wait for maintainer feedback
3. Get approval before starting work

**This saves everyone time.**

#### Setting Up Development Environment

```bash
# Clone the repo
git clone https://github.com/0xKirisame/shinkai-shoujo
cd shinkai-shoujo

# Install dependencies
go mod download

# Install development tools
go install golang.org/x/tools/cmd/goimports@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

# Run tests
go test ./...

# Run linter
staticcheck ./...

# Format code
goimports -w .
```

#### Code Style

We follow **standard Go conventions** with a few additions:

**Files should be short:**
```go
// Good: internal/correlation/engine.go (~200 lines)
// Bad: internal/correlation/engine.go (1000+ lines)

// If a file is >300 lines, split it
```

**Functions should be simple:**
```go
// Good: Does one thing, ~20 lines
func correlate(assigned []string, observed map[string]int) Result {
    // Simple logic
}

// Bad: Does many things, 100+ lines
func analyzeAndGenerateAndEmail(...) {
    // Too much
}
```

**Comments for "why", not "what":**
```go
// Good:
// Fuzzy matching handles edge cases like lambda:Invoke → lambda:InvokeFunction
if contains(privilege, action) {

// Bad:
// Check if privilege contains action
if contains(privilege, action) {
```

**Error messages should be actionable:**
```go
// Good:
return fmt.Errorf("failed to connect to OTel collector at %s: %w. Check that the collector is running and the endpoint is correct", endpoint, err)

// Bad:
return fmt.Errorf("connection failed: %w", err)
```

**Avoid premature abstraction:**
```go
// Good: Simple, clear
func (e *Engine) Analyze() error {
    roles := e.fetchRoles()
    usage := e.fetchUsage()
    return e.correlate(roles, usage)
}

// Bad: Over-engineered
type Analyzer interface {
    Analyze(context.Context) error
}
type RoleFetcher interface {
    Fetch() ([]Role, error)
}
// ... 5 more interfaces
```

#### Testing

**We value simple, readable tests over high coverage:**

```go
// Good test: Clear, self-contained
func TestCorrelateFindsUnusedPrivileges(t *testing.T) {
    assigned := []string{"s3:GetObject", "s3:DeleteBucket"}
    observed := map[string]int{"s3:GetObject": 100}
    
    result := correlate(assigned, observed)
    
    if len(result.Unused) != 1 {
        t.Errorf("expected 1 unused privilege, got %d", len(result.Unused))
    }
    if result.Unused[0] != "s3:DeleteBucket" {
        t.Errorf("expected s3:DeleteBucket to be unused")
    }
}

// Bad test: Hard to understand
func TestCorrelate(t *testing.T) {
    testCases := []struct{
        name string
        // ... 20 fields
    }{
        // ... 50 test cases
    }
    // Generic test loop
}
```

**Coverage targets:**
- Core logic (correlation, analysis): 80%+
- I/O code (OTel receiver, DB): 50%+
- CLI commands: Manual testing is fine

**Run tests:**
```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./internal/correlation/...

# Verbose
go test -v ./...
```

#### Commit Messages

**Format:**
```
<type>: <short summary> (<50 chars)

<detailed description if needed>

Fixes #123
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `refactor:` Code refactoring (no behavior change)
- `test:` Adding/updating tests
- `chore:` Tooling, dependencies, etc.

**Examples:**
```
feat: add GCP IAM support

Adds support for analyzing GCP IAM roles using the same
correlation engine. Uses GCP Cloud Asset API for role discovery.

Fixes #42

---

fix: handle lambda:Invoke → lambda:InvokeFunction mapping

AWS SDK emits "Invoke" but IAM uses "InvokeFunction".
Added special case mapping for this and other known mismatches.

Fixes #87

---

docs: clarify OTel configuration in README

Users were confused about which OTel endpoint to use.
Added examples for common OTel collector setups.
```

#### Pull Request Process

1. **Fork the repo** and create a branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes:**
   - Write code
   - Add tests
   - Update docs
   - Run tests and linters

3. **Commit with good messages:**
   ```bash
   git commit -m "feat: add GCP support"
   ```

4. **Push and open PR:**
   ```bash
   git push origin feat/my-feature
   ```
   Then open PR on GitHub

5. **PR template:**
   ```markdown
   **What does this PR do?**
   Brief description
   
   **Why?**
   What problem does it solve?
   
   **How was it tested?**
   - [ ] Unit tests added
   - [ ] Manual testing done
   - [ ] Tested with real OTel collector
   
   **Checklist:**
   - [ ] Tests pass (`go test ./...`)
   - [ ] Linter passes (`staticcheck ./...`)
   - [ ] Documentation updated
   - [ ] CHANGELOG.md updated (if user-facing)
   
   **Breaking changes?**
   None / Yes (describe)
   
   Fixes #<issue number>
   ```

6. **Code review:**
   - Maintainer will review within 1-3 days
   - Address feedback
   - Once approved, we'll merge

7. **After merge:**
   - Your change will be in the next release
   - You'll be credited in CHANGELOG

---

## Areas Needing Help

### 🔴 High Priority

**1. AWS SDK Special Cases**

Some AWS operations have different names in SDKs vs IAM:

```go
// internal/correlation/special_cases.go

var specialCases = map[string]string{
    "lambda:Invoke": "lambda:InvokeFunction",
    "s3:HeadObject": "s3:GetObject",
    "s3:HeadBucket": "s3:ListBucket",
    // Add more as you discover them
}
```

**How to help:**
1. Find OTel traces that don't match IAM privileges
2. Look up the correct IAM action in AWS docs
3. Add mapping to `special_cases.go`
4. Add test case

**Good first issue:** [#12](https://github.com/0xKirisame/shinkai-shoujo/issues/12)

---

**2. Multi-Cloud Support**

We need GCP IAM and Azure RBAC support.

**What's needed:**
- `internal/gcp/scraper.go` - Fetch GCP IAM bindings
- `internal/azure/scraper.go` - Fetch Azure role assignments
- Update correlation engine to handle GCP/Azure formats
- Tests with mock GCP/Azure clients

**Skills needed:** Experience with GCP Cloud Asset API or Azure Resource Graph

**Epic:** [#24](https://github.com/0xKirisame/shinkai-shoujo/issues/24)

---

**3. CloudTrail Fallback**

When OTel coverage is low, fall back to CloudTrail.

**What's needed:**
- `internal/aws/cloudtrail.go` - Parse CloudTrail logs
- Detect low OTel coverage (< 50% of expected API calls)
- Merge CloudTrail data with OTel data
- Tests with sample CloudTrail logs

**Skills needed:** AWS CloudTrail, S3, parsing large JSON files

**Issue:** [#31](https://github.com/0xKirisame/shinkai-shoujo/issues/31)

---

### 🟡 Medium Priority

**4. Grafana Dashboard**

Adding shinkai shoujo to grafana:
- Add more visualizations (heatmaps, trends)
- Per-team/per-environment views
- Alert templates
- Variables for filtering

**Skills needed:** Grafana dashboard JSON, PromQL

**Issue:** [#45](https://github.com/0xKirisame/shinkai-shoujo/issues/45)

---

**5. Scheduled Job Auto-Detection**

Automatically exclude privileges used by cron jobs.

**What's needed:**
- Parse CloudWatch Events / EventBridge schedules
- Calculate job frequency
- Auto-exclude if frequency < observation window
- Add to correlation engine

**Skills needed:** AWS CloudWatch Events API

**Issue:** [#52](https://github.com/0xKirisame/shinkai-shoujo/issues/52)

---

**6. Documentation**

Always needed:
- More examples in README
- Troubleshooting guide
- Blog posts about your usage
- Video tutorials
- Translations (non-English)

**Skills needed:** Writing, explaining technical concepts

**Good first issue:** Any documentation issue

---

### 🟢 Low Priority (Nice to Have)

**7. Resource-Level Privilege Detection**

Track not just "s3:GetObject" but "s3:GetObject on bucket X"

**What's needed:**
- Parse resource ARNs from OTel attributes
- Update correlation to match resource-specific policies
- More complex, lower ROI

**Issue:** [#78](https://github.com/0xKirisame/shinkai-shoujo/issues/78)

---

**8. Performance Optimization**

If you find performance issues:
- Profile with `pprof`
- Optimize hot paths
- But: Don't optimize prematurely
- Measure first

**Issue:** [#89](https://github.com/0xKirisame/shinkai-shoujo/issues/89)

---

## What We Won't Accept

**To keep Shinkai simple, we will NOT merge:**

❌ **Custom web UI**
- Use Grafana instead
- If you need custom UI, fork and maintain separately

❌ **Real-time streaming analysis**
- Batch processing is sufficient
- Real-time adds complexity

❌ **Agent deployment**
- Defeats the "agentless" value prop
- Use OTel collector if you need agents

❌ **Proprietary integrations**
- Only open standards (OTel, Prometheus)
- No vendor lock-in

❌ **Complex ML/AI**
- String matching works fine
- ML adds complexity and maintenance burden

❌ **Features that solve <10% use cases**
- Keep scope tight
- Let users extend via plugins/forks

---

## Code of Conduct

**Be kind. Be respectful.**

We're all here to build a better tool.

**Unacceptable:**
- Harassment, discrimination
- Aggressive or dismissive comments
- Demanding features or timelines

**Encouraged:**
- Constructive criticism
- Helping other contributors
- Sharing your use case
- Patience with review process

**If someone violates this:**
Report to maintainers via email: Contact@kirisame.dev

---

## Questions?

**Before asking:**
1. Read the [README](README.md)
2. Check [existing issues](https://github.com/0xKirisame/shinkai-shoujo/issues)
3. Search [discussions](https://github.com/0xKirisame/shinkai-shoujo/discussions)

**Still stuck?**
- Open a [discussion](https://github.com/0xKirisame/shinkai-shoujo/discussions/new)
  
**Don't:**
- Email maintainers directly (use GitHub)
- Open issues for questions (use discussions)

---

## Recognition

**Contributors are credited in:**
- CHANGELOG.md (for each release)
- README.md (top contributors)
- Git history (your commits)

**We deeply appreciate:**
- Bug reports (you make it better)
- Code contributions (you make it faster)
- Documentation (you make it clearer)
- Advocacy (you make it known)

**Thank you for contributing to making IAM security simpler!**

---

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

See [LICENSE](LICENSE) for details.
