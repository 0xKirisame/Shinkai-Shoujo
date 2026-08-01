# Shinkai Shoujo

<div align="center">

<img src="https://static.wikia.nocookie.net/vocaloid/images/a/a7/%E6%B7%B1%E6%B5%B7%E5%B0%91%E5%A5%B3_-deep_sea_girl-.png/revision/latest?cb=20221216124014" alt="Deep Sea Girl" width="500" />

*"Deep sea girl, pulled by her arm... The marine snow sings a song of blessing"*

</div>

CloudTrail-free AWS IAM usage observability from dedicated OpenTelemetry events.

Shinkai receives one OTel log event for each AWS SDK operation performed by an application, stores those events in ClickHouse, snapshots the application's assigned IAM policies through read-only IAM APIs, and exposes usage, inventory, and conservative correlation results to Grafana and HTTP clients.

## Scope

Shinkai answers application-level questions:

- Which IAM actions did this workload successfully use?
- How often did it use each action?
- When was each action first and last observed?
- Which assigned exact actions were not observed in the selected window?
- Which grants remain unresolved because they contain wildcards, `NotAction`, conditions, boundaries, or other IAM semantics?
- Which operations were denied or failed?

It does not use CloudTrail. It intentionally does not observe console activity, CLI activity, uninstrumented callers, or AWS-managed service-to-service behavior.

## Architecture

```text
Application AWS SDK middleware
  -> dedicated OTel log event
  -> OTel Collector logs pipeline
  -> Shinkai OTLP/HTTP receiver
  -> ClickHouse raw events and hourly aggregates

AWS IAM read APIs
  -> complete immutable identity-policy snapshot
  -> ClickHouse inventory tables

ClickHouse
  -> Shinkai JSON query API
  -> Grafana ClickHouse datasource
```

Activity and inventory are independent sources:

```text
dedicated OTel events = what instrumented applications did
read-only IAM APIs    = what their roles are assigned
```

## Event Contract

AWS SDK middleware must emit one OTel log record per attempted SDK operation. This signal is independent of trace sampling.

The required native OTel event name is:

```text
LogRecord.event_name = shinkai.aws_api_call
```

Modern OTel event APIs set `LogRecord.event_name`. For compatibility with log SDKs that do not yet expose that field, Shinkai and the provided Collector pipeline also accept an `event.name` attribute with the same value.

Required attributes:

| Attribute | Description |
|---|---|
| `event.id` | Stable unique ID required for retry deduplication |
| `aws.iam.role.arn` | IAM role ARN or STS assumed-role ARN |
| `aws.service` | AWS service, such as `s3` |
| `aws.operation` | SDK operation, such as `GetObject` |
| `shinkai.outcome` | `success`, `denied`, or `failed` |

Recommended resource attributes:

| Attribute | Description |
|---|---|
| `cloud.account.id` | AWS account ID; otherwise derived from the role ARN |
| `service.name` | Workload name |
| `deployment.environment.name` | Environment |
| `shinkai.tenant.id` | Tenant; defaults to `default` |

Recommended event attributes:

| Attribute | Description |
|---|---|
| `aws.iam.action` | Canonical IAM action when known |
| `aws.request_id` | AWS request ID |

Trace and span IDs on the OTel log record are retained for trace drilldown.

Example logical event:

```json
{
  "event.name": "shinkai.aws_api_call",
  "event.id": "018f65d4-4ae8-7c22-91eb-3d70c95f81a1",
  "aws.iam.role.arn": "arn:aws:iam::123456789012:role/PaymentsAPI",
  "cloud.account.id": "123456789012",
  "aws.service": "s3",
  "aws.operation": "GetObject",
  "aws.iam.action": "s3:GetObject",
  "shinkai.outcome": "success",
  "aws.request_id": "request-id",
  "service.name": "payments-api",
  "deployment.environment.name": "production"
}
```

Only `success` proves permission usage. Denied and failed events are stored but never count as used permissions.

## Role Identity

Generic AWS SDK spans do not reliably contain the caller's role. The application instrumentation must attach identity to the dedicated event or its OTel resource.

Common sources are:

- One cached `sts:GetCallerIdentity` call during application startup
- `AWS_ROLE_ARN` for EKS IRSA
- EKS Pod Identity metadata
- ECS task-role metadata
- EC2 instance profile metadata
- Lambda execution-role configuration

Shinkai normalizes this STS ARN:

```text
arn:aws:sts::123456789012:assumed-role/PaymentsAPI/session-id
```

to this IAM role ARN:

```text
arn:aws:iam::123456789012:role/PaymentsAPI
```

Applications that assume multiple roles at runtime must attach the active role to each event rather than using one process-level resource attribute.

## IAM Access

Shinkai uses these six read-only IAM APIs:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:ListRoles",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetRolePolicy"
    ],
    "Resource": "*"
  }]
}
```

For managed policies, `GetPolicy` supplies the active `DefaultVersionId`, which is then passed to `GetPolicyVersion`. Shared managed policies are cached during a scrape.

Every snapshot preserves:

- Managed and inline identity-policy provenance
- `Allow` and `Deny`
- `Action` and `NotAction`
- `Resource` and `NotResource`
- Conditions and statement IDs
- Policy ARN, name, and active version
- Decoded raw policy documents

A snapshot becomes queryable only after every listed role and attached or inline policy has been fetched and written. A partial AWS failure never replaces the latest complete snapshot.

The six-API scope does not include `iam:GetRole`. AWS does not return permissions-boundary details from `ListRoles`, so boundaries are not inventoried. They are explicitly treated as an external constraint rather than silently modeled as grants.

## Quick Start

Prerequisites:

- Docker Compose
- AWS credentials containing the read-only IAM permissions above

Start ClickHouse, Shinkai, the OTel Collector, and Grafana:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=... # if applicable
docker compose up --build
```

Development endpoints:

| Service | Endpoint |
|---|---|
| OTel Collector gRPC | `localhost:4317` |
| OTel Collector HTTP | `http://localhost:4318` |
| Shinkai query API | `http://localhost:9090` |
| Grafana | `http://localhost:3000` |
| ClickHouse native | `localhost:9000` |
| ClickHouse HTTP | `http://localhost:8123` |

Development credentials and tokens are in `compose.yaml` and `deploy/config.yaml`. Replace them outside local development.

Test the backend:

```bash
curl http://localhost:9090/healthz

curl \
  -H 'Authorization: Bearer shinkai-dev-api-token' \
  'http://localhost:9090/api/v1/usage?account_id=123456789012'
```

Grafana starts with a provisioned ClickHouse datasource and the **Shinkai Shoujo IAM Usage** dashboard. It includes usage frequency, first/last use, denied calls, exact unobserved candidates after a configurable minimum coverage period, and unresolved wildcard grants. The initial development login is `admin` / `admin`.

## Build From Source

```bash
go build -o shinkai-shoujo ./cmd/shinkai-shoujo
./shinkai-shoujo init
```

The generated config contains ClickHouse, OTLP receiver, AWS, observation-window, and HTTP API settings.

Useful commands:

```bash
# Fetch and publish one complete identity-policy snapshot
shinkai-shoujo scrape

# Fetch a snapshot and run a one-time analysis
shinkai-shoujo analyze

# Report from the latest complete snapshot
shinkai-shoujo report --account-id 123456789012

# Run OTLP ingestion, the query API, and periodic IAM snapshots
shinkai-shoujo daemon --interval 6h

# Export review data; Terraform output contains locals only and changes no IAM resources
shinkai-shoujo generate json --account-id 123456789012
shinkai-shoujo generate yaml --account-id 123456789012
shinkai-shoujo generate terraform --account-id 123456789012
```

## Configuration

```yaml
otel:
  endpoint: "127.0.0.1:4318"
  role_attribute: "aws.iam.role.arn"
  auth_token: ""

aws:
  region: "us-east-1"
  account_id: "123456789012"

observation:
  window_days: 30
  min_observation_days: 7

clickhouse:
  addresses: ["localhost:9000"]
  database: "shinkai_shoujo"
  username: "default"
  password: ""
  secure: false
  dial_timeout: "5s"
  retention_days: 90

http:
  endpoint: "127.0.0.1:9090"
  auth_token: ""
```

Non-loopback OTLP or HTTP binds require a bearer token. TLS should be terminated by a trusted reverse proxy when traffic crosses hosts. ClickHouse TLS is enabled with `clickhouse.secure`.

## Query API

All endpoints except `/healthz` require `Authorization: Bearer <http.auth_token>` when a token is configured.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | ClickHouse connectivity |
| `GET /metrics` | Prometheus backend metrics |
| `GET /api/v1/usage` | Frequency and first/last use by role and action |
| `GET /api/v1/inventory` | Latest complete identity-policy snapshot |
| `GET /api/v1/analysis` | Assigned-versus-observed correlation |

Usage filters:

```text
tenant_id
account_id
role_arn
workload
environment
since (RFC3339)
until (RFC3339)
```

Analysis filters:

```text
tenant_id
account_id
window_days
```

## ClickHouse Tables

Shinkai creates and migrates:

- `usage_events`: immutable raw OTel usage events
- `permission_usage_hourly`: unique successful-event aggregates
- `permission_usage_hourly_mv`: successful-event materialized view
- `collector_heartbeats`: received and accepted event coverage
- `iam_snapshots`: complete snapshot publication records
- `iam_roles`: role identity per snapshot
- `iam_policy_statements`: lossless policy statement inventory

Raw events and hourly aggregates use the configured retention TTL.

## Interpretation

Results use conservative language:

- `used`: successfully observed and covered by an assigned action or pattern
- `candidate_unused`: assigned exact action not observed in the selected window
- `unresolved`: wildcard, `NotAction`, unsupported mapping, or semantics that cannot safely become a removal candidate
- `denied`: attempted and rejected, never evidence of use
- `failed`: failed for another reason, never evidence of use

Only roles represented by OTel usage events are analyzed. This prevents unrelated infrastructure roles from being labeled unused.

Terraform output is review-only HCL containing local values. It deliberately creates no IAM policies or attachments.

## Limitations

- AWS SDK operations do not always map one-to-one to IAM actions.
- Dependent permissions such as `iam:PassRole` may be required without a separate SDK operation.
- Shared roles combine activity from every workload using that role.
- Uninstrumented code is invisible.
- Reliable frequency requires the dedicated event signal not to be sampled or dropped.
- Permissions boundaries, SCPs, session policies, and resource-based policies are not currently inventoried.

These limitations are surfaced as unresolved semantics or review warnings rather than silently converted into removal instructions.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```

Set `CLICKHOUSE_TEST_ADDR=localhost:9000` to run the opt-in ClickHouse integration test.

## License

Apache 2.0. See `LICENSE`.
