package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for shinkai-shoujo.
type Metrics struct {
	SpansReceived    prometheus.Counter
	SpansSkipped     prometheus.Counter
	IAMRolesScraped  prometheus.Gauge
	AnalysisRuns     prometheus.Counter
	UnusedPrivileges *prometheus.GaugeVec
	AnalysisDuration prometheus.Histogram
	registry         prometheus.Registerer
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

	spansReceived := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shinkai_spans_received_total",
		Help: "Total number of OTel spans received.",
	})
	factory(spansReceived)

	spansSkipped := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "shinkai_spans_skipped_total",
		Help: "Total number of OTel spans skipped (missing required attributes).",
	})
	factory(spansSkipped)

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

	unusedPrivileges := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "shinkai_unused_privileges",
		Help: "Number of unused privileges per IAM role.",
	}, []string{"iam_role", "risk_level"})
	factory(unusedPrivileges)

	analysisDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "shinkai_analysis_duration_seconds",
		Help:    "Duration of correlation analysis runs.",
		Buckets: prometheus.DefBuckets,
	})
	factory(analysisDuration)

	return &Metrics{
		SpansReceived:    spansReceived,
		SpansSkipped:     spansSkipped,
		IAMRolesScraped:  iamRolesScraped,
		AnalysisRuns:     analysisRuns,
		UnusedPrivileges: unusedPrivileges,
		AnalysisDuration: analysisDuration,
		registry:         reg,
	}
}

// Handler returns an HTTP handler for the /metrics endpoint using the default registry.
func Handler() http.Handler {
	return promhttp.Handler()
}
