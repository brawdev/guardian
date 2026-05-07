package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/brawdev/guardian/internal/urlanalyzer"
)

type analyzeURLRequest struct {
	URL string `json:"url"`
}

func AnalyzeURL(safeBrowsingKey, virusTotalKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req analyzeURLRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
			writeError(w, http.StatusBadRequest, "campo 'url' requerido")
			return
		}

		result, err := urlanalyzer.Analyze(req.URL, safeBrowsingKey, virusTotalKey)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}
