package prometheusserver

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func ConnectToPrometheus() {
	http.Handle("/metrics", promhttp.Handler())

	// Uruchamiamy serwer HTTP na porcie 8080
	log.Println("Serwer nasłuchuje na porcie 8080. Sprawdź http://localhost:8080/metrics")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
