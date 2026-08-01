package receiver

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"

	"github.com/0xKirisame/shinkai-shoujo/internal/correlation"
	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

const usageEventName = "shinkai.aws_api_call"

// parseLogs extracts dedicated AWS API call events from an OTLP logs payload.
func parseLogs(
	resourceLogs []*logsv1.ResourceLogs,
	roleAttribute string,
	now time.Time,
	log *slog.Logger,
	m *metrics.Metrics,
) ([]storage.UsageEvent, uint64) {
	now = now.UTC()
	var (
		events   []storage.UsageEvent
		received uint64
	)

	for _, resourceLog := range resourceLogs {
		resourceAttrs := attributes(resourceLog.GetResource().GetAttributes())
		for _, scopeLog := range resourceLog.GetScopeLogs() {
			for _, record := range scopeLog.GetLogRecords() {
				received++
				m.EventsReceived.Inc()

				recordAttrs := attributes(record.GetAttributes())
				if record.GetEventName() != usageEventName && recordAttrs["event.name"] != usageEventName && record.GetBody().GetStringValue() != usageEventName {
					skipLogRecord(log, m, record, "not a dedicated AWS API call event")
					continue
				}
				attrs := mergeAttributes(resourceAttrs, recordAttrs)

				role := firstAttribute(attrs, roleAttribute, "aws.iam.role.arn", "aws.iam.role")
				service := firstAttribute(attrs, "aws.service", "rpc.service")
				operation := firstAttribute(attrs, "aws.operation", "rpc.method")
				if role == "" || service == "" || operation == "" {
					skipLogRecord(log, m, record, "missing role, service, or operation")
					continue
				}

				outcome, ok := normalizeOutcome(firstAttribute(attrs, "shinkai.outcome", "event.outcome", "outcome"))
				if !ok {
					skipLogRecord(log, m, record, "missing or unknown outcome")
					continue
				}

				eventTime, ok := logTimestamp(record, now)
				if !ok || eventTime.After(now.Add(5*time.Minute)) {
					skipLogRecord(log, m, record, "timestamp is too far in the future")
					continue
				}

				eventID := strings.TrimSpace(attrs["event.id"])
				if eventID == "" {
					skipLogRecord(log, m, record, "missing event ID")
					continue
				}

				role = normalizeRoleARN(role)
				accountID := strings.TrimSpace(attrs["cloud.account.id"])
				if accountID == "" {
					accountID = accountIDFromARN(role)
				}
				tenantID := strings.TrimSpace(attrs["shinkai.tenant.id"])
				if tenantID == "" {
					tenantID = "default"
				}
				iamAction := strings.TrimSpace(attrs["aws.iam.action"])
				if iamAction == "" {
					iamAction = correlation.MapSDKToIAM(strings.ToLower(service) + ":" + operation)
				}

				events = append(events, storage.UsageEvent{
					EventID:      eventID,
					EventTime:    eventTime,
					ReceivedAt:   now,
					TenantID:     tenantID,
					AccountID:    accountID,
					RoleARN:      role,
					Workload:     strings.TrimSpace(attrs["service.name"]),
					Environment:  firstAttribute(attrs, "deployment.environment.name", "deployment.environment"),
					AWSService:   service,
					SDKOperation: operation,
					IAMAction:    iamAction,
					Outcome:      outcome,
					RequestID:    strings.TrimSpace(attrs["aws.request_id"]),
					TraceID:      hex.EncodeToString(record.GetTraceId()),
					SpanID:       hex.EncodeToString(record.GetSpanId()),
				})
			}
		}
	}

	return events, received
}

func attributes(attrs []*commonv1.KeyValue) map[string]string {
	values := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		if attr == nil || attr.Value == nil {
			continue
		}
		if value, ok := attr.Value.Value.(*commonv1.AnyValue_StringValue); ok {
			values[attr.Key] = value.StringValue
		}
	}
	return values
}

func mergeAttributes(resourceAttrs, recordAttrs map[string]string) map[string]string {
	merged := make(map[string]string, len(resourceAttrs)+len(recordAttrs))
	for key, value := range resourceAttrs {
		merged[key] = value
	}
	for key, value := range recordAttrs {
		merged[key] = value
	}
	return merged
}

func firstAttribute(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attrs[key]); key != "" && value != "" {
			return value
		}
	}
	return ""
}

func normalizeOutcome(outcome string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "success", "succeeded", "ok":
		return "success", true
	case "access_denied", "accessdenied", "denied":
		return "denied", true
	case "fail", "failed", "error":
		return "failed", true
	default:
		return "", false
	}
}

func normalizeRoleARN(role string) string {
	role = strings.TrimSpace(role)
	parts := strings.SplitN(role, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "sts" || !strings.HasPrefix(parts[5], "assumed-role/") {
		return role
	}
	assumedRole := strings.TrimPrefix(parts[5], "assumed-role/")
	separator := strings.LastIndexByte(assumedRole, '/')
	if separator <= 0 || separator == len(assumedRole)-1 {
		return role
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", parts[1], parts[4], assumedRole[:separator])
}

func accountIDFromARN(role string) string {
	parts := strings.SplitN(role, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" {
		return parts[4]
	}
	return ""
}

func logTimestamp(record *logsv1.LogRecord, now time.Time) (time.Time, bool) {
	nanos := record.GetTimeUnixNano()
	if nanos == 0 {
		nanos = record.GetObservedTimeUnixNano()
	}
	if nanos == 0 {
		return now, true
	}
	if nanos > math.MaxInt64 {
		return time.Time{}, false
	}
	return time.Unix(0, int64(nanos)).UTC(), true
}

func skipLogRecord(log *slog.Logger, m *metrics.Metrics, record *logsv1.LogRecord, reason string) {
	log.Debug("skipping log record", "reason", reason, "span_id", hex.EncodeToString(record.GetSpanId()))
	m.EventsSkipped.Inc()
}
