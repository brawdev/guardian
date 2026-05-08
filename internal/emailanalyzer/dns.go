package emailanalyzer

import (
	"net"
	"strings"
	"time"
)

type SPFResult struct {
	HasRecord bool   `json:"has_record,omitempty"`
	Policy    string `json:"policy,omitempty"` // "-all", "~all", "?all", "+all"
	IsStrict  bool   `json:"is_strict,omitempty"`
	Error     string `json:"error,omitempty"`
}

type DMARCResult struct {
	HasRecord bool   `json:"has_record,omitempty"`
	Policy    string `json:"policy,omitempty"` // "none", "quarantine", "reject"
	IsStrict  bool   `json:"is_strict,omitempty"`
	Pct       int    `json:"pct,omitempty"` // porcentaje de emails sujetos a la política
	Error     string `json:"error,omitempty"`
}

func CheckSPF(domain string) SPFResult {
	if domain == "" {
		return SPFResult{Error: "dominio vacío"}
	}

	ch := make(chan SPFResult, 1)
	go func() {
		records, err := net.LookupTXT(domain)
		if err != nil {
			ch <- SPFResult{Error: "no se pudo consultar DNS: " + err.Error()}
			return
		}
		for _, r := range records {
			if strings.HasPrefix(strings.ToLower(r), "v=spf1") {
				ch <- parseSPF(r)
				return
			}
		}
		ch <- SPFResult{HasRecord: false, Error: "sin registro SPF"}
	}()

	select {
	case <-time.After(5 * time.Second):
		return SPFResult{Error: "timeout en consulta SPF"}
	case res := <-ch:
		return res
	}
}

func parseSPF(record string) SPFResult {
	result := SPFResult{HasRecord: true}
	parts := strings.Fields(strings.ToLower(record))
	for _, p := range parts {
		switch p {
		case "-all":
			result.Policy = "-all"
			result.IsStrict = true
		case "~all":
			result.Policy = "~all"
		case "?all":
			result.Policy = "?all"
		case "+all":
			result.Policy = "+all"
		}
	}
	if result.Policy == "" {
		result.Policy = "sin directiva all"
	}
	return result
}

func CheckDMARC(domain string) DMARCResult {
	if domain == "" {
		return DMARCResult{Error: "dominio vacío"}
	}

	ch := make(chan DMARCResult, 1)
	go func() {
		records, err := net.LookupTXT("_dmarc." + domain)
		if err != nil {
			ch <- DMARCResult{Error: "no se pudo consultar DNS: " + err.Error()}
			return
		}
		for _, r := range records {
			if strings.HasPrefix(strings.ToLower(r), "v=dmarc1") {
				ch <- parseDMARC(r)
				return
			}
		}
		ch <- DMARCResult{HasRecord: false, Error: "sin registro DMARC"}
	}()

	select {
	case <-time.After(5 * time.Second):
		return DMARCResult{Error: "timeout en consulta DMARC"}
	case res := <-ch:
		return res
	}
}

func parseDMARC(record string) DMARCResult {
	result := DMARCResult{HasRecord: true, Pct: 100}
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "p=") {
			result.Policy = strings.TrimPrefix(part, "p=")
			result.IsStrict = result.Policy == "reject" || result.Policy == "quarantine"
		}
		if strings.HasPrefix(part, "pct=") {
			pctStr := strings.TrimPrefix(part, "pct=")
			pct := 0
			for _, c := range pctStr {
				if c >= '0' && c <= '9' {
					pct = pct*10 + int(c-'0')
				}
			}
			result.Pct = pct
		}
	}
	if result.Policy == "" {
		result.Policy = "none"
	}
	return result
}
