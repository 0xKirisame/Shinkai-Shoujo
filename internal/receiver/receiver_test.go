package receiver

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/0xKirisame/shinkai-shoujo/internal/metrics"
	"github.com/0xKirisame/shinkai-shoujo/internal/storage"
)

func testMetrics() *metrics.Metrics {
	return metrics.NewWithRegistry(prometheus.NewRegistry())
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func makeKV(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}},
	}
}

func makeResourceLogs(resourceAttrs []*commonv1.KeyValue, records ...*logsv1.LogRecord) []*logsv1.ResourceLogs {
	return []*logsv1.ResourceLogs{{
		Resource:  &resourcev1.Resource{Attributes: resourceAttrs},
		ScopeLogs: []*logsv1.ScopeLogs{{LogRecords: records}},
	}}
}

func makeExportRequest(resourceAttrs []*commonv1.KeyValue, records ...*logsv1.LogRecord) *collectorlogsv1.ExportLogsServiceRequest {
	return &collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: makeResourceLogs(resourceAttrs, records...)}
}

func dedicatedRecord(outcome string, extra ...*commonv1.KeyValue) *logsv1.LogRecord {
	attrs := []*commonv1.KeyValue{
		makeKV("event.name", usageEventName),
		makeKV("aws.service", "S3"),
		makeKV("aws.operation", "GetObject"),
	}
	if outcome != "" {
		attrs = append(attrs, makeKV("shinkai.outcome", outcome))
	}
	attrs = append(attrs, extra...)
	return &logsv1.LogRecord{Attributes: attrs}
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("writing metric: %v", err)
	}
	return metric.GetCounter().GetValue()
}

func TestParseLogsHappyPathFromResourceAttributes(t *testing.T) {
	now := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	eventTime := now.Add(-time.Minute)
	m := testMetrics()
	record := &logsv1.LogRecord{
		EventName:            usageEventName,
		TimeUnixNano:         uint64(eventTime.UnixNano()),
		ObservedTimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
		TraceId:              []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		SpanId:               []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}
	resources := makeResourceLogs([]*commonv1.KeyValue{
		makeKV("aws.iam.role.arn", "arn:aws:iam::123456789012:role/MyRole"),
		makeKV("cloud.account.id", "123456789012"),
		makeKV("aws.service", "S3"),
		makeKV("aws.operation", "GetObject"),
		makeKV("aws.iam.action", "s3:GetObject"),
		makeKV("shinkai.outcome", "OK"),
		makeKV("event.id", "event-1"),
		makeKV("shinkai.tenant.id", "tenant-1"),
		makeKV("service.name", "checkout"),
		makeKV("deployment.environment.name", "production"),
		makeKV("aws.request_id", "request-1"),
	}, record)

	events, received := parseLogs(resources, "custom.role", now, testLogger(), m)
	if received != 1 || len(events) != 1 {
		t.Fatalf("parseLogs() received %d and returned %d events, want 1 and 1", received, len(events))
	}
	event := events[0]
	if event.EventID != "event-1" || !event.EventTime.Equal(eventTime) || !event.ReceivedAt.Equal(now) {
		t.Errorf("unexpected event times or ID: %+v", event)
	}
	if event.TenantID != "tenant-1" || event.AccountID != "123456789012" || event.RoleARN != "arn:aws:iam::123456789012:role/MyRole" {
		t.Errorf("unexpected event identity: %+v", event)
	}
	if event.Workload != "checkout" || event.Environment != "production" || event.AWSService != "S3" || event.SDKOperation != "GetObject" {
		t.Errorf("unexpected event context: %+v", event)
	}
	if event.IAMAction != "s3:GetObject" || event.Outcome != "success" || event.RequestID != "request-1" {
		t.Errorf("unexpected event action: %+v", event)
	}
	if event.TraceID != "000102030405060708090a0b0c0d0e0f" || event.SpanID != "0102030405060708" {
		t.Errorf("unexpected trace context: %+v", event)
	}
	if got := counterValue(t, m.EventsReceived); got != 1 {
		t.Errorf("received metric = %v, want 1", got)
	}
	if got := counterValue(t, m.EventsSkipped); got != 0 {
		t.Errorf("skipped metric = %v, want 0", got)
	}
}

func TestParseLogsRecordOverridesResourceAndConfiguredRole(t *testing.T) {
	now := time.Now().UTC()
	record := dedicatedRecord("succeeded",
		makeKV("event.id", "override-event"),
		makeKV("identity.role", "arn:aws:iam::222222222222:role/RecordRole"),
		makeKV("aws.service", "Lambda"),
		makeKV("aws.operation", "Invoke"),
		makeKV("service.name", "record-workload"),
		makeKV("deployment.environment", "staging"),
	)
	resources := makeResourceLogs([]*commonv1.KeyValue{
		makeKV("identity.role", "arn:aws:iam::111111111111:role/ResourceRole"),
		makeKV("aws.iam.role.arn", "arn:aws:iam::111111111111:role/FallbackRole"),
		makeKV("aws.service", "S3"),
		makeKV("aws.operation", "GetObject"),
		makeKV("service.name", "resource-workload"),
	}, record)

	events, _ := parseLogs(resources, "identity.role", now, testLogger(), testMetrics())
	if len(events) != 1 {
		t.Fatalf("parseLogs() returned %d events, want 1", len(events))
	}
	event := events[0]
	if event.RoleARN != "arn:aws:iam::222222222222:role/RecordRole" || event.AccountID != "222222222222" {
		t.Errorf("record role did not override resource role: %+v", event)
	}
	if event.AWSService != "Lambda" || event.SDKOperation != "Invoke" || event.IAMAction != "lambda:InvokeFunction" {
		t.Errorf("record action did not override resource action: %+v", event)
	}
	if event.Workload != "record-workload" || event.Environment != "staging" {
		t.Errorf("record context did not override resource context: %+v", event)
	}
}

func TestParseLogsNormalizesAssumedRoleAndUsesObservedTime(t *testing.T) {
	now := time.Now().UTC()
	observed := now.Add(-2 * time.Minute).Truncate(time.Nanosecond)
	record := &logsv1.LogRecord{
		ObservedTimeUnixNano: uint64(observed.UnixNano()),
		Body:                 &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: usageEventName}},
		Attributes: []*commonv1.KeyValue{
			makeKV("event.id", "observed-event"),
			makeKV("aws.iam.role", "arn:aws:sts::123456789012:assumed-role/team/MyRole/session-name"),
			makeKV("rpc.service", "DynamoDB"),
			makeKV("rpc.method", "PutItem"),
			makeKV("event.outcome", "success"),
		},
	}

	events, _ := parseLogs(makeResourceLogs(nil, record), "", now, testLogger(), testMetrics())
	if len(events) != 1 {
		t.Fatalf("parseLogs() returned %d events, want 1", len(events))
	}
	event := events[0]
	if event.RoleARN != "arn:aws:iam::123456789012:role/team/MyRole" || event.AccountID != "123456789012" {
		t.Errorf("unexpected normalized identity: %+v", event)
	}
	if !event.EventTime.Equal(observed) || event.TenantID != "default" || event.IAMAction != "dynamodb:PutItem" {
		t.Errorf("unexpected derived fields: %+v", event)
	}
	if event.EventID != "observed-event" {
		t.Errorf("event ID = %q, want observed-event", event.EventID)
	}
}

func TestParseLogsRequiresEventID(t *testing.T) {
	now := time.Now().UTC()
	m := testMetrics()
	missing := dedicatedRecord("success")
	empty := dedicatedRecord("success", makeKV("event.id", "   "))
	events, received := parseLogs(makeResourceLogs([]*commonv1.KeyValue{
		makeKV("aws.iam.role.arn", "arn:aws:iam::123456789012:role/Test"),
	}, missing, empty), "", now, testLogger(), m)

	if received != 2 || len(events) != 0 {
		t.Fatalf("parseLogs() received %d and returned %d events, want 2 and 0", received, len(events))
	}
	if got := counterValue(t, m.EventsSkipped); got != 2 {
		t.Errorf("skipped metric = %v, want 2", got)
	}
}

func TestParseLogsRetainsDeniedEvent(t *testing.T) {
	now := time.Now().UTC()
	record := dedicatedRecord("access_denied", makeKV("event.id", "denied-event"), makeKV("aws.iam.action", "s3:ListBucket"))
	events, _ := parseLogs(makeResourceLogs([]*commonv1.KeyValue{
		makeKV("aws.iam.role.arn", "arn:aws:iam::123456789012:role/Test"),
	}, record), "", now, testLogger(), testMetrics())
	if len(events) != 1 || events[0].Outcome != "denied" || events[0].IAMAction != "s3:ListBucket" {
		t.Fatalf("denied event was not retained: %+v", events)
	}
}

func TestParseLogsSkipsInvalidAndUnrelatedRecords(t *testing.T) {
	now := time.Now().UTC()
	m := testMetrics()
	missingOutcome := dedicatedRecord("")
	unknownOutcome := dedicatedRecord("maybe")
	unrelated := dedicatedRecord("success")
	unrelated.Attributes[0] = makeKV("event.name", "other.event")
	future := dedicatedRecord("success")
	future.TimeUnixNano = uint64(now.Add(6 * time.Minute).UnixNano())
	resources := makeResourceLogs([]*commonv1.KeyValue{
		makeKV("event.name", usageEventName),
		makeKV("aws.iam.role.arn", "arn:aws:iam::123456789012:role/Test"),
	}, missingOutcome, unknownOutcome, unrelated, future)

	events, received := parseLogs(resources, "", now, testLogger(), m)
	if received != 4 || len(events) != 0 {
		t.Fatalf("parseLogs() received %d and returned %d events, want 4 and 0", received, len(events))
	}
	if got := counterValue(t, m.EventsReceived); got != 4 {
		t.Errorf("received metric = %v, want 4", got)
	}
	if got := counterValue(t, m.EventsSkipped); got != 4 {
		t.Errorf("skipped metric = %v, want 4", got)
	}
}

type fakeEventStore struct {
	batchCalls     int
	heartbeatCalls int
	events         []storage.UsageEvent
	heartbeatAt    time.Time
	received       uint64
	accepted       uint64
	batchErr       error
	heartbeatErr   error
}

func (f *fakeEventStore) BatchRecordUsageEvents(_ context.Context, events []storage.UsageEvent) error {
	f.batchCalls++
	f.events = append([]storage.UsageEvent(nil), events...)
	return f.batchErr
}

func (f *fakeEventStore) RecordCollectorHeartbeat(_ context.Context, at time.Time, received, accepted uint64) error {
	f.heartbeatCalls++
	f.heartbeatAt = at
	f.received = received
	f.accepted = accepted
	return f.heartbeatErr
}

func newTestServer(t *testing.T, token string, store eventStore) *Server {
	t.Helper()
	server, err := New("http://127.0.0.1:4318", "identity.role", token, store, testLogger(), testMetrics())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return server
}

func serveRequest(server *Server, method, path, contentType, contentEncoding, authorization string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	response := httptest.NewRecorder()
	server.srv.Handler.ServeHTTP(response, req)
	return response
}

func validExportRequest() *collectorlogsv1.ExportLogsServiceRequest {
	record := dedicatedRecord("success", makeKV("event.id", "http-event"))
	return makeExportRequest([]*commonv1.KeyValue{
		makeKV("identity.role", "arn:aws:iam::123456789012:role/HTTPRole"),
	}, record)
}

func TestHandleLogsRejectsJSON(t *testing.T) {
	store := &fakeEventStore{}
	server := newTestServer(t, "", store)
	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/json; charset=utf-8", "", "", []byte(`{}`))
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", response.Code)
	}
	if store.batchCalls != 0 || store.heartbeatCalls != 0 {
		t.Errorf("JSON request reached store: %+v", store)
	}
}

func TestHandleLogsGzipProtobuf(t *testing.T) {
	store := &fakeEventStore{}
	server := newTestServer(t, "", store)
	request := validExportRequest()
	record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	record.Attributes = record.Attributes[1:]
	record.Body = &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: usageEventName}}
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(body); err != nil {
		t.Fatalf("compressing request: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}

	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "gzip", "", compressed.Bytes())
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/x-protobuf" {
		t.Errorf("response content type = %q, want application/x-protobuf", response.Header().Get("Content-Type"))
	}
	otlpResponse := &collectorlogsv1.ExportLogsServiceResponse{}
	if err := proto.Unmarshal(response.Body.Bytes(), otlpResponse); err != nil {
		t.Errorf("invalid protobuf OTLP response: %v", err)
	}
	if otlpResponse.PartialSuccess != nil {
		t.Errorf("partial success = %+v, want nil", otlpResponse.PartialSuccess)
	}
	if store.batchCalls != 1 || store.heartbeatCalls != 1 || store.received != 1 || store.accepted != 1 {
		t.Errorf("unexpected store calls: %+v", store)
	}
}

func TestHandleLogsAuthentication(t *testing.T) {
	body, err := proto.Marshal(validExportRequest())
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	for _, test := range []struct {
		name   string
		header string
		want   int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong", header: "Bearer wrong-token", want: http.StatusUnauthorized},
		{name: "valid", header: "Bearer secret-token", want: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeEventStore{}
			server := newTestServer(t, "secret-token", store)
			response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "", test.header, body)
			if response.Code != test.want {
				t.Errorf("status = %d, want %d", response.Code, test.want)
			}
			if test.want == http.StatusUnauthorized && (store.batchCalls != 0 || store.heartbeatCalls != 0) {
				t.Errorf("unauthorized request reached store: %+v", store)
			}
		})
	}
}

func TestHandleLogsRejectsUnsupportedContentType(t *testing.T) {
	store := &fakeEventStore{}
	server := newTestServer(t, "", store)
	response := serveRequest(server, http.MethodPost, "/v1/logs", "text/plain", "", "", []byte("{}"))
	if response.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", response.Code)
	}
	if store.batchCalls != 0 || store.heartbeatCalls != 0 {
		t.Errorf("unsupported request reached store: %+v", store)
	}
}

func TestHandleLogsRejectsOversizedDecompressedBody(t *testing.T) {
	store := &fakeEventStore{}
	server := newTestServer(t, "", store)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(bytes.Repeat([]byte{'x'}, maxBodyBytes+1)); err != nil {
		t.Fatalf("compressing request: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}

	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "gzip", "", compressed.Bytes())
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", response.Code)
	}
	if store.batchCalls != 0 || store.heartbeatCalls != 0 {
		t.Errorf("oversized request reached store: %+v", store)
	}
}

func TestHandleLogsHeartbeatsWhenNoEventsAccepted(t *testing.T) {
	store := &fakeEventStore{}
	server := newTestServer(t, "", store)
	request := makeExportRequest(nil, &logsv1.LogRecord{Attributes: []*commonv1.KeyValue{makeKV("event.name", "other")}})
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "", "", body)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if store.batchCalls != 0 || store.heartbeatCalls != 1 || store.received != 1 || store.accepted != 0 {
		t.Errorf("unexpected store calls: %+v", store)
	}
}

func TestHandleLogsReturnsPartialSuccess(t *testing.T) {
	store := &fakeEventStore{}
	server := newTestServer(t, "", store)
	request := makeExportRequest([]*commonv1.KeyValue{
		makeKV("identity.role", "arn:aws:iam::123456789012:role/HTTPRole"),
	},
		dedicatedRecord("success", makeKV("event.id", "accepted-event")),
		dedicatedRecord("success"),
	)
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}

	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "", "", body)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	otlpResponse := &collectorlogsv1.ExportLogsServiceResponse{}
	if err := proto.Unmarshal(response.Body.Bytes(), otlpResponse); err != nil {
		t.Fatalf("unmarshalling response: %v", err)
	}
	partial := otlpResponse.GetPartialSuccess()
	if partial.GetRejectedLogRecords() != 1 || partial.GetErrorMessage() == "" {
		t.Errorf("partial success = %+v, want one rejection and an error message", partial)
	}
	if store.batchCalls != 1 || len(store.events) != 1 || store.received != 2 || store.accepted != 1 {
		t.Errorf("unexpected store calls: %+v", store)
	}
}

func TestHandleLogsEventStorageFailureIsRetryable(t *testing.T) {
	body, err := proto.Marshal(validExportRequest())
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	store := &fakeEventStore{batchErr: errors.New("batch failed")}
	server := newTestServer(t, "", store)
	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "", "", body)
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", response.Code)
	}
	if response.Header().Get("Content-Type") != "application/x-protobuf" {
		t.Errorf("content type = %q, want application/x-protobuf", response.Header().Get("Content-Type"))
	}
	status := &statuspb.Status{}
	if err := proto.Unmarshal(response.Body.Bytes(), status); err != nil {
		t.Fatalf("unmarshalling status: %v", err)
	}
	if status.GetCode() != int32(codes.Unavailable) || status.GetMessage() == "" {
		t.Errorf("status response = %+v, want UNAVAILABLE with a message", status)
	}
	if store.batchCalls != 1 || store.heartbeatCalls != 1 || store.accepted != 0 {
		t.Errorf("unexpected store calls: %+v", store)
	}
}

func TestHandleLogsHeartbeatFailureStillSucceeds(t *testing.T) {
	body, err := proto.Marshal(validExportRequest())
	if err != nil {
		t.Fatalf("marshalling request: %v", err)
	}
	store := &fakeEventStore{heartbeatErr: errors.New("heartbeat failed")}
	server := newTestServer(t, "", store)
	response := serveRequest(server, http.MethodPost, "/v1/logs", "application/x-protobuf", "", "", body)
	if response.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", response.Code)
	}
	if err := proto.Unmarshal(response.Body.Bytes(), &collectorlogsv1.ExportLogsServiceResponse{}); err != nil {
		t.Errorf("invalid protobuf OTLP response: %v", err)
	}
	if store.batchCalls != 1 || store.heartbeatCalls != 1 || store.accepted != 1 {
		t.Errorf("unexpected store calls: %+v", store)
	}
}

func TestEndpointAddress(t *testing.T) {
	for _, endpoint := range []string{"127.0.0.1:4318", "http://127.0.0.1:4318"} {
		if _, err := endpointAddress(endpoint); err != nil {
			t.Errorf("endpointAddress(%q) error: %v", endpoint, err)
		}
	}
	if _, err := endpointAddress("https://127.0.0.1:4318"); err == nil {
		t.Error("endpointAddress() accepted HTTPS endpoint")
	}
}

func TestServerDoesNotExposeTraceEndpoint(t *testing.T) {
	server := newTestServer(t, "", &fakeEventStore{})
	response := serveRequest(server, http.MethodPost, "/v1/traces", "application/x-protobuf", "", "", nil)
	if response.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", response.Code)
	}
}

func TestServerStopsWhenContextIsCanceled(t *testing.T) {
	server, err := New("127.0.0.1:0", "", "", &fakeEventStore{}, testLogger(), testMetrics())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Start(ctx)
	}()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start() error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start() did not return after context cancellation")
	}
}
