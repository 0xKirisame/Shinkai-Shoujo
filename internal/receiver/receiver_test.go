package receiver

import (
	"testing"
	"time"

	"log/slog"
	"os"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
)

func testMetrics() *metrics.Metrics {
	return metrics.NewWithRegistry(prometheus.NewRegistry())
}

func makeKV(key, val string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: val}},
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestParseTraces_HappyPath(t *testing.T) {
	m := testMetrics()
	log := testLogger()

	now := uint64(time.Now().UnixNano())
	resourceSpans := []*tracev1.ResourceSpans{
		{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{
					makeKV("aws.iam.role", "arn:aws:iam::123:role/MyRole"),
				},
			},
			ScopeSpans: []*tracev1.ScopeSpans{
				{
					Spans: []*tracev1.Span{
						{
							SpanId:           []byte{1, 2, 3, 4, 5, 6, 7, 8},
							StartTimeUnixNano: now,
							Attributes: []*commonv1.KeyValue{
								makeKV("aws.service", "S3"),
								makeKV("aws.operation", "GetObject"),
							},
						},
					},
				},
			},
		},
	}

	records := parseTraces(resourceSpans, log, m)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].IAMRole != "arn:aws:iam::123:role/MyRole" {
		t.Errorf("unexpected role: %s", records[0].IAMRole)
	}
	if records[0].Privilege != "s3:GetObject" {
		t.Errorf("unexpected privilege: %s", records[0].Privilege)
	}
}

func TestParseTraces_MissingRole(t *testing.T) {
	m := testMetrics()
	log := testLogger()

	resourceSpans := []*tracev1.ResourceSpans{
		{
			Resource: &resourcev1.Resource{
				// No aws.iam.role attribute
				Attributes: []*commonv1.KeyValue{},
			},
			ScopeSpans: []*tracev1.ScopeSpans{
				{
					Spans: []*tracev1.Span{
						{
							Attributes: []*commonv1.KeyValue{
								makeKV("aws.service", "S3"),
								makeKV("aws.operation", "GetObject"),
							},
						},
					},
				},
			},
		},
	}

	records := parseTraces(resourceSpans, log, m)
	if len(records) != 0 {
		t.Errorf("expected 0 records when role is missing, got %d", len(records))
	}
}

func TestParseTraces_MissingService(t *testing.T) {
	m := testMetrics()
	log := testLogger()

	resourceSpans := []*tracev1.ResourceSpans{
		{
			Resource: &resourcev1.Resource{
				Attributes: []*commonv1.KeyValue{
					makeKV("aws.iam.role", "role/MyRole"),
				},
			},
			ScopeSpans: []*tracev1.ScopeSpans{
				{
					Spans: []*tracev1.Span{
						{
							Attributes: []*commonv1.KeyValue{
								// Missing aws.service
								makeKV("aws.operation", "GetObject"),
							},
						},
					},
				},
			},
		},
	}

	records := parseTraces(resourceSpans, log, m)
	if len(records) != 0 {
		t.Errorf("expected 0 records when service is missing, got %d", len(records))
	}
}

func TestNormalizePrivilege(t *testing.T) {
	tests := []struct {
		service   string
		operation string
		expected  string
	}{
		{"S3", "GetObject", "s3:GetObject"},
		{"s3", "PutObject", "s3:PutObject"},
		{"Lambda", "Invoke", "lambda:Invoke"},
		{"EC2", "DescribeInstances", "ec2:DescribeInstances"},
	}
	for _, tt := range tests {
		got := normalizePrivilege(tt.service, tt.operation)
		if got != tt.expected {
			t.Errorf("normalizePrivilege(%q, %q) = %q, want %q", tt.service, tt.operation, got, tt.expected)
		}
	}
}
