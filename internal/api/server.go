package api

import (
	"net/http"
	"time"

	"github.com/brawdev/guardian/internal/api/handlers"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Config struct {
	SafeBrowsingKey string
	VirusTotalKey   string
}

func NewRouter(cfg Config) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/analyze/url", handlers.AnalyzeURL(cfg.SafeBrowsingKey, cfg.VirusTotalKey))
		r.Post("/analyze/seller", handlers.AnalyzeSeller())
		r.Post("/analyze/email", handlers.AnalyzeEmail(cfg.SafeBrowsingKey, cfg.VirusTotalKey))
		r.Post("/analyze/phone", handlers.AnalyzePhone())
	})

	return r
}
