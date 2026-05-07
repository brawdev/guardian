package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/brawdev/guardian/internal/sellerscraper"
)

type analyzeSellerRequest struct {
	URL      string `json:"url"`
	Platform string `json:"platform"`
}

func AnalyzeSeller() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req analyzeSellerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
			writeError(w, http.StatusBadRequest, "campo 'url' requerido")
			return
		}

		result, err := sellerscraper.Analyze(req.URL, req.Platform)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}
