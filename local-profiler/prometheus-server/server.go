package prometheusserver

import (
	"context"
	"fmt"
	synchronization "local-profiler/synchronization"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var cacheMisses *prometheus.GaugeVec

func SaveMetrics(PID string, totalCount int64) error {

	cacheMisses.WithLabelValues(PID).Set(float64(totalCount))

	return nil
}

func ConnectToPrometheus(sync *synchronization.SyncStruct) error {
	defer sync.Wg.Done()

	cacheMisses = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cache_misses_total",
			Help: "Number of cache misses from PID",
		}, []string{"PID"},
	)

	reg := prometheus.NewRegistry()

	reg.MustRegister(cacheMisses)

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
