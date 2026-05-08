package urlanalyzer

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type Result struct {
	URL              string           `json:"url,omitempty"`
	OriginalURL      string           `json:"original_url,omitempty"`
	IsShortURL       bool             `json:"is_short_url,omitempty"`
	Hostname         string           `json:"hostname,omitempty"`
	SuspiciousTLD    bool             `json:"suspicious_tld,omitempty"`
	TLD              string           `json:"tld,omitempty"`
	SpoofedSubdomain string           `json:"spoofed_subdomain,omitempty"`
	Typo             TypoResult       `json:"typo,omitempty"`
	Whois            WhoisResult      `json:"whois,omitempty"`
	Redirects        RedirectResult   `json:"redirects,omitempty"`
	Reputation       ReputationResult `json:"reputation,omitempty"`
	Tranco           TrancoResult     `json:"tranco,omitempty"`
	GeoIP            GeoIPResult      `json:"geo_ip,omitempty"`
	RiskScore        int              `json:"risk_score,omitempty"`
	RiskLevel        string           `json:"risk_level,omitempty"`
	Flags            []string         `json:"flags,omitempty"`
}

func Analyze(rawURL, safeBrowsingKey, virusTotalKey string) (Result, error) {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}

	// Expandir URL cortos antes de analizar
	analyzedURL := rawURL
	isShort := IsShortURL(rawURL)
	if isShort {
		if expanded, ok := ExpandShortURL(rawURL); ok {
			analyzedURL = expanded
		}
	}

	parsed, err := url.Parse(analyzedURL)
	if err != nil {
		return Result{}, err
	}

	result := Result{
		URL:      analyzedURL,
		Hostname: parsed.Hostname(),
	}
	if isShort {
		result.OriginalURL = rawURL
		result.IsShortURL = true
	}

	result.SuspiciousTLD, result.TLD = checkSuspiciousTLD(parsed.Hostname())
	result.SpoofedSubdomain = checkSpoofedSubdomain(parsed.Hostname())

	var wg sync.WaitGroup
	wg.Add(6)

	go func() { defer wg.Done(); result.Typo = CheckTyposquatting(parsed.Hostname()) }()
	go func() { defer wg.Done(); result.Whois = CheckWhois(parsed.Hostname()) }()
	go func() { defer wg.Done(); result.Redirects = CheckRedirects(rawURL) }()
	go func() { defer wg.Done(); result.Reputation = CheckReputation(rawURL, safeBrowsingKey, virusTotalKey) }()
	go func() { defer wg.Done(); result.Tranco = CheckTrancoRank(parsed.Hostname()) }()
	go func() { defer wg.Done(); result.GeoIP = CheckGeoIP(parsed.Hostname()) }()

	wg.Wait()

	result.RiskScore, result.Flags = calculateRisk(result)
	result.RiskLevel = scoreToLevel(result.RiskScore)

	return result, nil
}

func checkSuspiciousTLD(hostname string) (bool, string) {
	lower := strings.ToLower(hostname)
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(lower, tld) {
			return true, tld
		}
	}
	return false, ""
}

func checkSpoofedSubdomain(hostname string) string {
	spoofed := []string{"gov", "secure", "login", "account", "banking", "pagos", "pago", "verify", "update"}
	parts := strings.Split(strings.ToLower(hostname), ".")
	if len(parts) > 2 {
		sub := parts[0]
		for _, s := range spoofed {
			if sub == s {
				return sub
			}
		}
	}
	return ""
}

func calculateRisk(r Result) (int, []string) {
	score := 0
	var flags []string

	if r.IsShortURL {
		score += 10
		flags = append(flags, "URL corto ("+r.OriginalURL+") — destino real oculto antes de expandir")
	}

	if r.SuspiciousTLD {
		score += 30
		flags = append(flags, "TLD '"+r.TLD+"' frecuentemente usado en sitios de phishing y fraude")
	}

	if r.SpoofedSubdomain != "" {
		score += 25
		flags = append(flags, "subdominio '"+r.SpoofedSubdomain+".' usado para aparentar oficialidad")
	}

	if r.Typo.IsPunycode {
		score += 30
		flags = append(flags, "dominio Punycode/IDN: '"+r.Hostname+"' se muestra como '"+r.Typo.DecodedDomain+"'")
	}

	if r.Typo.IsTyposquat {
		score += 40
		switch r.Typo.MatchType {
		case "contains":
			flags = append(flags, "impersonación de marca: dominio contiene '"+r.Typo.ClosestBrand+"' (patrón info/pagos/soporte+marca)")
		case "homoglyph":
			flags = append(flags, "homoglifo: '"+r.Typo.Suspicious+"' imita a '"+r.Typo.ClosestBrand+"' con caracteres similares")
		default:
			flags = append(flags, "typosquatting: similar a '"+r.Typo.ClosestBrand+"' (distancia "+itoa(r.Typo.Distance)+")")
		}
	}

	if r.Whois.IsNew {
		score += 25
		flags = append(flags, "dominio nuevo: creado hace "+itoa(r.Whois.DomainAge)+" días")
	}

	if !r.Redirects.TLSValid {
		score += 20
		flags = append(flags, "SSL/TLS inválido o autofirmado")
	}

	if r.Redirects.CrossDomain {
		score += 15
		flags = append(flags, "redirecciona a dominio diferente")
	}

	if r.Redirects.HopCount >= 3 {
		score += 10
		flags = append(flags, "cadena de "+itoa(r.Redirects.HopCount)+" redirecciones")
	}

	if r.Reputation.SafeBrowsing.IsMalicious {
		score += 50
		flags = append(flags, "Google Safe Browsing: MALICIOSO ("+strings.Join(r.Reputation.SafeBrowsing.ThreatTypes, ", ")+")")
	}

	vt := r.Reputation.VirusTotal
	if vt.Error == "" && vt.IsMalicious {
		score += 50
		flags = append(flags, fmt.Sprintf("VirusTotal: %d/%d engines lo marcan malicioso (%s)", vt.Malicious, vt.TotalEngines, VTVendorSummary(vt.Vendors)))
	} else if vt.Error == "" && vt.Suspicious > 0 {
		score += 20
		flags = append(flags, fmt.Sprintf("VirusTotal: %d engines sospechoso", vt.Suspicious))
	}

	if r.Tranco.Error == "" && !r.Tranco.InTopList {
		score += 15
		flags = append(flags, "dominio no aparece en el top 1M de Tranco (desconocido o muy nuevo)")
	}

	if r.GeoIP.Error == "" && isHighRiskCountry(r.GeoIP.CountryCode) {
		score += 20
		flags = append(flags, "servidor alojado en país de alto riesgo: "+r.GeoIP.Country+" ("+r.GeoIP.CountryCode+")")
	}

	if r.GeoIP.Error == "" && r.GeoIP.IsHosting {
		score += 10
		flags = append(flags, "IP pertenece a infraestructura de hosting/datacenter ("+r.GeoIP.ISP+")")
	}

	if score > 100 {
		score = 100
	}
	return score, flags
}

func scoreToLevel(score int) string {
	switch {
	case score >= 75:
		return "CRITICO"
	case score >= 50:
		return "ALTO"
	case score >= 25:
		return "MEDIO"
	default:
		return "BAJO"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}
