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
		ct := r.Header.Get("Content-Type")

		if strings.HasPrefix(ct, "multipart/form-data") {
			analyzeEmailFile(w, r, safeBrowsingKey, virusTotalKey)
			return
		}

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

func analyzeEmailFile(w http.ResponseWriter, r *http.Request, safeBrowsingKey, virusTotalKey string) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "error al leer el formulario")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "campo 'file' requerido")
		return
	}
	defer file.Close()

	result, err := emailanalyzer.AnalyzeReader(file, safeBrowsingKey, virusTotalKey)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "no se pudo parsear el email: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}
