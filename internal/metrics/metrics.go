package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for shinkai-shoujo.
type Metrics struct {
	EventsReceived        prometheus.Counter
	EventsSkipped         prometheus.Counter
	IAMRolesScraped       prometheus.Gauge
	AnalysisRuns          prometheus.Counter
	CandidatePermissions  prometheus.Gauge
	UnresolvedPermissions prometheus.Gauge
	AnalysisDuration      prometheus.Histogram
	gatherer              prometheus.Gatherer
}

// New creates and registers all metrics with the default Prometheus registry.
func New() *Metrics {
	return NewWithRegistry(prometheus.DefaultRegisterer)
}

// NewWithRegistry creates metrics registered against the provided Registerer.
// Use prometheus.NewRegistry() in tests to avoid duplicate registration panics.
func NewWithRegistry(reg prometheus.Registerer) *Metrics {
	factory := func(c prometheus.Collector) prometheus.Collector {
		reg.MustRegister(c)
		return c
	}

	eventsReceived := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shinkai_events_received_total",
		Help: "Total number of dedicated OTel AWS usage events received.",
	})
	factory(eventsReceived)

	eventsSkipped := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shinkai_events_skipped_total",
		Help: "Total number of OTel log records skipped because they were not valid usage events.",
	})
	factory(eventsSkipped)

	iamRolesScraped := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shinkai_iam_roles_scraped",
		Help: "Number of IAM roles scraped in the last scrape.",
	})
	factory(iamRolesScraped)

	analysisRuns := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shinkai_analysis_runs_total",
		Help: "Total number of correlation analysis runs.",
	})
	factory(analysisRuns)

	candidatePermissions := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shinkai_candidate_unused_permissions",
		Help: "Number of candidate unused permissions in the most recent analysis.",
	})
	factory(candidatePermissions)

	unresolvedPermissions := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "shinkai_unresolved_permissions",
		Help: "Number of wildcard or semantically unresolved permissions in the most recent analysis.",
	})
	factory(unresolvedPermissions)

	analysisDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "shinkai_analysis_duration_seconds",
		Help:    "Duration of correlation analysis runs.",
		Buckets: prometheus.DefBuckets,
	})
	factory(analysisDuration)

	gatherer, ok := reg.(prometheus.Gatherer)
	if !ok {
		panic("BUG: registerer does not implement prometheus.Gatherer")
	}

	return &Metrics{
		EventsReceived:        eventsReceived,
		EventsSkipped:         eventsSkipped,
		IAMRolesScraped:       iamRolesScraped,
		AnalysisRuns:          analysisRuns,
		CandidatePermissions:  candidatePermissions,
		UnresolvedPermissions: unresolvedPermissions,
		AnalysisDuration:      analysisDuration,
		gatherer:              gatherer,
	}
}

// Handler returns an HTTP handler for the /metrics endpoint using the registry
// that was provided to NewWithRegistry. This ensures the handler only exposes
// metrics registered with this specific Metrics instance.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
}
