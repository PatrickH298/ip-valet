// Package metrics defines the Prometheus metrics. Worker and entry gauges are
// read from the database at scrape time by a custom collector.
package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// StreamCounter reports connected SSE streams.
type StreamCounter interface {
	WorkerStreams() map[string]int
	ClientStreams() int
}

// Metrics holds the registry and the directly updated metrics.
type Metrics struct {
	Registry    *prometheus.Registry
	Requests    *prometheus.CounterVec
	Duration    *prometheus.HistogramVec
	Submissions *prometheus.CounterVec
}

// New registers every metric. pool and streams feed the scrape-time collector.
func New(pool *pgxpool.Pool, streams StreamCounter, log *slog.Logger) *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ipvalet_http_requests_total", Help: "HTTP requests by route pattern, method and status.",
		}, []string{"route", "method", "status"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "ipvalet_http_request_duration_seconds", Help: "HTTP request duration by route pattern and method.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "method"}),
		Submissions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ipvalet_submissions_total", Help: "Submissions by result: accepted or the first failing code.",
		}, []string{"result"}),
	}
	m.Registry.MustRegister(m.Requests, m.Duration, m.Submissions,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		&dbCollector{pool: pool, streams: streams, log: log})
	return m
}

var (
	descRevision    = prometheus.NewDesc("ipvalet_revision", "Current global revision.", nil, nil)
	descApplied     = prometheus.NewDesc("ipvalet_worker_applied_revision", "Revision the worker last reported applying.", []string{"worker"}, nil)
	descLag         = prometheus.NewDesc("ipvalet_worker_revision_lag", "Current revision minus the worker's applied revision.", []string{"worker"}, nil)
	descLastSeen    = prometheus.NewDesc("ipvalet_worker_last_seen_timestamp_seconds", "Unix time of the worker's last status report.", []string{"worker"}, nil)
	descRejections  = prometheus.NewDesc("ipvalet_worker_rejections", "Prefixes the worker reported rejecting.", []string{"worker"}, nil)
	descWorkers     = prometheus.NewDesc("ipvalet_worker_streams", "Worker event streams connected to this instance.", []string{"worker"}, nil)
	descClients     = prometheus.NewDesc("ipvalet_client_streams", "Client event streams connected to this instance.", nil, nil)
	descEntriesLive = prometheus.NewDesc("ipvalet_entries_live", "Live, unexpired entries per realm.", []string{"realm"}, nil)
)

type dbCollector struct {
	pool    *pgxpool.Pool
	streams StreamCounter
	log     *slog.Logger
}

func (c *dbCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descRevision, descApplied, descLag, descLastSeen, descRejections,
		descWorkers, descClients, descEntriesLive} {
		ch <- d
	}
}

func (c *dbCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(descClients, prometheus.GaugeValue, float64(c.streams.ClientStreams()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rev int64
	if err := c.pool.QueryRow(ctx, `SELECT value FROM revision_counter`).Scan(&rev); err != nil {
		c.log.Warn("metrics: reading revision failed", "error", err.Error())
		return
	}
	ch <- prometheus.MustNewConstMetric(descRevision, prometheus.GaugeValue, float64(rev))

	workers := c.streams.WorkerStreams()
	rows, err := c.pool.Query(ctx, `
		SELECT t.id::text, t.name, t.applied_revision, t.last_seen_at,
		       (SELECT count(*) FROM worker_rejections r WHERE r.worker_id = t.id)
		FROM workers t ORDER BY t.name`)
	if err != nil {
		c.log.Warn("metrics: reading workers failed", "error", err.Error())
		return
	}
	for rows.Next() {
		var (
			id, name string
			applied  int64
			lastSeen *time.Time
			nRej     int64
		)
		if err := rows.Scan(&id, &name, &applied, &lastSeen, &nRej); err != nil {
			rows.Close()
			return
		}
		ch <- prometheus.MustNewConstMetric(descApplied, prometheus.GaugeValue, float64(applied), name)
		ch <- prometheus.MustNewConstMetric(descLag, prometheus.GaugeValue, float64(rev-applied), name)
		if lastSeen != nil {
			ch <- prometheus.MustNewConstMetric(descLastSeen, prometheus.GaugeValue, float64(lastSeen.UnixNano())/1e9, name)
		}
		ch <- prometheus.MustNewConstMetric(descRejections, prometheus.GaugeValue, float64(nRej), name)
		ch <- prometheus.MustNewConstMetric(descWorkers, prometheus.GaugeValue, float64(workers[id]), name)
	}
	rows.Close()

	rows, err = c.pool.Query(ctx, `
		SELECT realm::text, count(*) FROM entries
		WHERE deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		GROUP BY realm ORDER BY realm`)
	if err != nil {
		c.log.Warn("metrics: reading entries failed", "error", err.Error())
		return
	}
	defer rows.Close()
	for rows.Next() {
		var (
			realm string
			n     int64
		)
		if err := rows.Scan(&realm, &n); err != nil {
			return
		}
		ch <- prometheus.MustNewConstMetric(descEntriesLive, prometheus.GaugeValue, float64(n), realm)
	}
}
