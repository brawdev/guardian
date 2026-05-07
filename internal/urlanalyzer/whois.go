package urlanalyzer

import (
	"strings"
	"time"

	"github.com/likexian/whois"
)

type WhoisResult struct {
	DomainAge   int    `json:"domain_age,omitempty"`
	CreatedDate string `json:"created_date,omitempty"`
	IsNew       bool   `json:"is_new,omitempty"`
	Error       string `json:"error,omitempty"`
}

func CheckWhois(hostname string) WhoisResult {
	domain := extractRootDomain(hostname)
	raw, err := whois.Whois(domain)
	if err != nil {
		return WhoisResult{Error: err.Error()}
	}

	created := extractCreatedDate(raw)
	if created.IsZero() {
		return WhoisResult{Error: "no se pudo parsear fecha de creación"}
	}

	age := int(time.Since(created).Hours() / 24)
	return WhoisResult{
		DomainAge:   age,
		CreatedDate: created.Format("2006-01-02"),
		IsNew:       age < 90,
	}
}

func extractCreatedDate(raw string) time.Time {
	// Formatos comunes en respuestas WHOIS
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"02-Jan-2006",
		"2006-01-02",
	}
	keywords := []string{
		"creation date:", "created:", "registered:", "domain registered:",
		"registration date:", "created on:",
	}

	for _, line := range strings.Split(raw, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, kw := range keywords {
			if strings.HasPrefix(lower, kw) {
				val := strings.TrimSpace(line[len(kw):])
				for _, f := range formats {
					if t, err := time.Parse(f, val); err == nil {
						return t
					}
				}
			}
		}
	}
	return time.Time{}
}

func extractRootDomain(hostname string) string {
	hostname = strings.TrimPrefix(hostname, "www.")
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return hostname
}
