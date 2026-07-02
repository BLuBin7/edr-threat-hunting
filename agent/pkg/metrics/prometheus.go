package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type PrometheusExporter struct {
	port int

	// Metrics
	eventsProcessed   *prometheus.CounterVec
	alertsGenerated   *prometheus.CounterVec
	inferenceLatency  prometheus.Histogram
	memoryUsage       prometheus.Gauge
	chainsTracked     prometheus.Gauge
}

func NewPrometheusExporter(port int) *PrometheusExporter {
	exporter := &PrometheusExporter{
		port: port,

		eventsProcessed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "edr_agent_events_processed_total",
				Help: "Total number of telemetry events processed",
			},
			[]string{"event_type"},
		),

		alertsGenerated: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "edr_agent_alerts_generated_total",
				Help: "Total number of threat alerts generated",
			},
			[]string{"severity"},
		),

		inferenceLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "edr_agent_ml_inference_latency_seconds",
				Help:    "ML inference latency in seconds",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
			},
		),

		memoryUsage: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "edr_agent_memory_usage_mb",
				Help: "Agent memory usage in MB",
			},
		),

		chainsTracked: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "edr_agent_chains_tracked",
				Help: "Number of attack chains currently being tracked",
			},
		),
	}

	// Register metrics
	prometheus.MustRegister(exporter.eventsProcessed)
	prometheus.MustRegister(exporter.alertsGenerated)
	prometheus.MustRegister(exporter.inferenceLatency)
	prometheus.MustRegister(exporter.memoryUsage)
	prometheus.MustRegister(exporter.chainsTracked)

	return exporter
}

func (e *PrometheusExporter) Start() {
	http.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf(":%d", e.port)

	log.WithField("port", e.port).Info("Metrics exporter started")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.WithError(err).Fatal("Failed to start metrics server")
	}
}

func (e *PrometheusExporter) IncEventsProcessed(eventType string) {
	e.eventsProcessed.WithLabelValues(eventType).Inc()
}

func (e *PrometheusExporter) IncAlertsGenerated(severity string) {
	e.alertsGenerated.WithLabelValues(severity).Inc()
}

func (e *PrometheusExporter) ObserveInferenceLatency(seconds float64) {
	e.inferenceLatency.Observe(seconds)
}

func (e *PrometheusExporter) SetMemoryUsage(mb float64) {
	e.memoryUsage.Set(mb)
}

func (e *PrometheusExporter) SetChainsTracked(count float64) {
	e.chainsTracked.Set(count)
}
