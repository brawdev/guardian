package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/brawdev/guardian/internal/emailanalyzer"
)

type analyzeEmailRequest struct {
	Content string `json:"content"`
}

func AnalyzeEmail(safeBrowsingKey, virusTotalKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req analyzeEmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Content) == "" {
			writeError(w, http.StatusBadRequest, "campo 'content' requerido")
			return
		}

		result, err := emailanalyzer.AnalyzeReader(strings.NewReader(req.Content), safeBrowsingKey, virusTotalKey)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "no se pudo parsear el email: "+err.Error())
			return
		}

		writeJSON(w, http.StatusOK, result)
	}
}
