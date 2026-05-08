package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/brawdev/guardian/internal/phoneanalyzer"
)

type analyzePhoneRequest struct {
	Phone          string `json:"phone"`
	CountryContext string `json:"country_context"`
}

func AnalyzePhone() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req analyzePhoneRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Phone) == "" {
			writeError(w, http.StatusBadRequest, "campo 'phone' requerido")
			return
		}

		result := phoneanalyzer.Analyze(req.Phone, req.CountryContext)
		writeJSON(w, http.StatusOK, result)
	}
}
