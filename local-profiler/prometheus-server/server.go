package prometheusserver

import (
	"context"
	"fmt"
	"local-profiler/modules"
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

func ConnectToPrometheus(sync *modules.SyncStruct) error {
	defer sync.Wg.Done()
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	recordMetrics(m)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	fmt.Println("Starting Go server at localhost:8080/metrics")

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Błąd serwera Prometheus: %v", err)
		}
	}()

	<-sync.Ctx.Done()
	fmt.Println("Receive closing signal. Turning off Prometheus server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Error shuting down server : %v\n", err)
		return err
	}

	fmt.Println("Prometheus shutdown successfully")
	return nil
}
