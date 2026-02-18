package receiver

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

// PrivilegeRecord is a parsed privilege observation from an OTel span.
type PrivilegeRecord struct {
	Timestamp time.Time
	IAMRole   string
	Privilege string
}

// parseTraces extracts privilege records from an ExportTraceServiceRequest.
func parseTraces(
	resourceSpans []*tracev1.ResourceSpans,
	log *slog.Logger,
	m *metrics.Metrics,
) []storage.PrivilegeUsageRecord {
	var records []storage.PrivilegeUsageRecord

	for _, rs := range resourceSpans {
		// Extract aws.iam.role from resource attributes
		iamRole := attrValue(rs.GetResource().GetAttributes(), "aws.iam.role")
		if iamRole == "" {
			log.Debug("skipping ResourceSpans: missing aws.iam.role resource attribute")
			continue
		}

		for _, ss := range rs.GetScopeSpans() {
			for _, span := range ss.GetSpans() {
				m.SpansReceived.Inc()

				service := attrValue(span.GetAttributes(), "aws.service")
				operation := attrValue(span.GetAttributes(), "aws.operation")

				if service == "" || operation == "" {
					log.Debug("skipping span: missing aws.service or aws.operation",
						"span_id", fmt.Sprintf("%x", span.GetSpanId()),
						"iam_role", iamRole,
					)
					m.SpansSkipped.Inc()
					continue
				}

				priv := normalizePrivilege(service, operation)
				ts := spanTimestamp(span)

				records = append(records, storage.PrivilegeUsageRecord{
					Timestamp: ts,
					IAMRole:   iamRole,
					Privilege: priv,
					CallCount: 1,
				})
			}
		}
	}
	return records
}

// normalizePrivilege produces "service:Operation" from span attributes.
// Service is lowercased; operation preserves original casing.
func normalizePrivilege(service, operation string) string {
	return fmt.Sprintf("%s:%s", strings.ToLower(service), operation)
}

// attrValue returns the string value of a named attribute, or "" if not found.
func attrValue(attrs []*commonv1.KeyValue, key string) string {
	for _, kv := range attrs {
		if kv.GetKey() == key {
			if sv := kv.GetValue().GetStringValue(); sv != "" {
				return sv
			}
		}
	}
	return ""
}

// spanTimestamp converts a span's start time from nanoseconds to time.Time.
// Falls back to current time if the span timestamp is zero.
func spanTimestamp(span *tracev1.Span) time.Time {
	if span.GetStartTimeUnixNano() != 0 {
		return time.Unix(0, int64(span.GetStartTimeUnixNano()))
	}
	return time.Now()
}
