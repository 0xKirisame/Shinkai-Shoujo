# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Shinkai Shoujo** is a Go CLI tool that identifies unused AWS IAM privileges by correlating existing OpenTelemetry traces against IAM-assigned permissions. It requires no agents, no eBPF, and no production deployments — only read-only IAM access and an existing OTel collector endpoint.

## Build & Run

```bash
# Download dependencies
go mod download

# Build binary
go build -o shinkai-shoujo cmd/shinkai-shoujo/main.go

# Run tests
go test ./...

# Run a single test package
go test ./internal/correlation/...

# Run locally
go run cmd/shinkai-shoujo/main.go analyze
```

## Intended Architecture

The project follows a standard Go project layout. Key components to implement:

### Data Flow
1. **OTel Receiver** (`internal/receiver/`) — Listens on OTLP/HTTP, parses incoming trace spans, extracts `aws.iam.role` + `aws.service`/`aws.operation` attributes, writes to SQLite.
2. **IAM Scraper** (`internal/scraper/`) — Calls read-only AWS IAM APIs (`ListRoles`, `ListAttachedRolePolicies`, `GetPolicyVersion`) to fetch assigned privileges per role; stores in SQLite.
3. **Correlation Engine** (`internal/correlation/`) — Queries SQLite for the configured observation window, computes `assigned - used = unused` via set operations (no ML/heuristics).
4. **Output Generator** (`internal/generator/`) — Produces Terraform HCL, JSON, or YAML from correlation results.
5. **Output Generator** (`internal/generator/`) — Produces Terraform HCL, JSON, or YAML from correlation results.
5. **Metrics Exporter** (`internal/metrics/`) — Exposes a Prometheus `/metrics` endpoint; Grafana is the intended visualization layer (no built-in web UI).
6. **CLI** (`cmd/shinkai-shoujo/`) — Entry point; subcommands: `analyze`, `report`, `generate`, `daemon`, `init`.

### Storage (SQLite)
Two primary tables:
- `privilege_usage` — per-span records: `(timestamp, iam_role, privilege, call_count)`
- `analysis_results` — weekly snapshots: `(analysis_date, iam_role, assigned_privileges JSON, used_privileges JSON, unused_privileges JSON, risk_level)`

Indices on `privilege_usage(iam_role)` and `privilege_usage(timestamp)` are required for performance.

### Configuration
Config file at `~/.shinkai-shoujo/config.yaml`. Key fields: `otel.endpoint`, `aws.region`, `observation.window_days`, `observation.min_observation_days`, `storage.path`.

### OTel Trace Format Expected
Spans must carry:
- Resource attribute `aws.iam.role` (ARN or role name)
- Span attributes `aws.service` and `aws.operation`

Privilege normalization: `fmt.Sprintf("%s:%s", strings.ToLower(service), operation)` → e.g., `s3:GetObject`.

### AWS SDK Operation → IAM Action Mapping
Some SDK operation names differ from IAM action names (e.g., `lambda:Invoke` → `lambda:InvokeFunction`). A mapping layer is needed in the correlation engine.

## Key Design Constraints

- **Read-only IAM access only** — the tool must never modify IAM.
- **Never auto-apply Terraform** — output is always written to a file for manual review.
- **All data stays local** — no external telemetry; SQLite is the only storage backend.
- Risk classification: privileges matching `Delete*`/`Terminate*` → HIGH, `Create*`/`Modify*` → MEDIUM, `Describe*`/`List*` → LOW.
