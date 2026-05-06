package urlanalyzer

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

type RedirectResult struct {
	Chain        []string
	FinalURL     string
	HopCount     int
	CrossDomain  bool // cambia de dominio en el camino
	TLSValid     bool
	TLSIssuer    string
	Error        string
}

func CheckRedirects(rawURL string) RedirectResult {
	result := RedirectResult{TLSValid: true}
	visited := map[string]bool{}
	current := rawURL
	initialHost := extractHost(rawURL)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // manejamos redirects manualmente
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	for i := 0; i < 10; i++ {
		if visited[current] {
			result.Error = "redirect loop detectado"
			break
		}
		visited[current] = true
		result.Chain = append(result.Chain, current)

		resp, err := client.Get(current)
		if err != nil {
			// Intentar sin verificación TLS para reportar el error específico
			insecureClient := &http.Client{
				Timeout:       10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
				Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			}
			resp2, err2 := insecureClient.Get(current)
			if err2 == nil {
				resp2.Body.Close()
				result.TLSValid = false
				result.Error = fmt.Sprintf("TLS inválido: %v", err)
			} else {
				result.Error = err.Error()
			}
			break
		}

		// Capturar info TLS del primer request HTTPS
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			result.TLSIssuer = resp.TLS.PeerCertificates[0].Issuer.Organization[0]
		}

		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}
			if extractHost(location) != initialHost {
				result.CrossDomain = true
			}
			current = location
			result.HopCount++
		} else {
			result.FinalURL = current
			break
		}
	}

	if result.FinalURL == "" && len(result.Chain) > 0 {
		result.FinalURL = result.Chain[len(result.Chain)-1]
	}
	return result
}

func extractHost(rawURL string) string {
	// Extracción simple sin importar net/url para evitar dependencia circular
	s := rawURL
	if idx := len("https://"); len(s) > idx {
		s = s[idx:]
	} else if idx := len("http://"); len(s) > idx {
		s = s[idx:]
	}
	for i, c := range s {
		if c == '/' || c == ':' || c == '?' {
			return s[:i]
		}
	}
	return s
}
