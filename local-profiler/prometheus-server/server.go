package prometheusserver

import (
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	opsProcessed prometheus.Counter
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		opsProcessed: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "myapp_processed_ops_total",
			Help: "The total number of processed events",
		}),
	}
	return m
}

func recordMetrics(m *metrics) {
	go func() {
		for {
			m.opsProcessed.Inc()
			time.Sleep(2 * time.Second)
		}
	}()
}

func ConnectToPrometheus() {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	recordMetrics(m)

	log.Println("Starting Go server at localhost:8080/metrics")

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	http.ListenAndServe(":8080", nil)
}
