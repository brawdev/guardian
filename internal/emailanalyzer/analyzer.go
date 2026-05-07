package emailanalyzer

import (
	"io"

	"github.com/brawdev/guardian/internal/urlanalyzer"
)

type LinkAnalysis struct {
	URL       string
	RiskLevel string
	RiskScore int
	TopFlag   string
}

type Result struct {
	File             string
	Subject          string
	From             string
	Headers          HeaderResult
	Body             BodyResult
	LinkResults      []LinkAnalysis
	RiskScore        int
	RiskLevel        string
	Flags            []string
	HeadersAvailable bool
}

func Analyze(path, safeBrowsingKey, virusTotalKey string) (Result, error) {
	pe, err := ParseFile(path)
	if err != nil {
		return Result{}, err
	}
	result := analyzeEmail(pe, safeBrowsingKey, virusTotalKey)
	result.File = path
	return result, nil
}

func AnalyzeReader(r io.Reader, safeBrowsingKey, virusTotalKey string) (Result, error) {
	pe, err := Parse(r)
	if err != nil {
		return Result{}, err
	}
	return analyzeEmail(pe, safeBrowsingKey, virusTotalKey), nil
}

func analyzeEmail(pe ParsedEmail, safeBrowsingKey, virusTotalKey string) Result {
	result := Result{
		Subject:          pe.Subject,
		From:             pe.From,
		HeadersAvailable: pe.HeadersAvailable,
	}
	if pe.HeadersAvailable {
		result.Headers = CheckHeaders(pe)
	}
	result.Body = CheckBody(pe, pe.FromDomain)
	result.LinkResults = analyzeLinks(result.Body.SuspiciousLinks, safeBrowsingKey, virusTotalKey)
	result.RiskScore, result.Flags = calculateRisk(result)
	result.RiskLevel = scoreToLevel(result.RiskScore)
	return result
}

func analyzeLinks(links []string, safeBrowsingKey, virusTotalKey string) []LinkAnalysis {
	if len(links) == 0 {
		return nil
	}
	limit := 5
	if len(links) < limit {
		limit = len(links)
	}
	var results []LinkAnalysis
	for _, link := range links[:limit] {
		r, err := urlanalyzer.Analyze(link, safeBrowsingKey, virusTotalKey)
		if err != nil {
			continue
		}
		la := LinkAnalysis{
			URL:       link,
			RiskLevel: r.RiskLevel,
			RiskScore: r.RiskScore,
		}
		if len(r.Flags) > 0 {
			la.TopFlag = r.Flags[0]
		}
		results = append(results, la)
	}
	return results
}

func calculateRisk(r Result) (int, []string) {
	score := 0
	var flags []string

	h := r.Headers

	// From-domain imita una marca pero no es el dominio oficial
	if h.ImpersonatedBrand != "" && !h.IsOfficialDomain {
		score += 45
		flags = append(flags, "dominio del remitente '"+h.FromDomain+"' suplanta a '"+h.ImpersonatedBrand+"'")
	}

	// DKIM firmado por dominio diferente al remitente
	if !h.DKIMAligned && len(h.DKIMSigners) > 0 {
		score += 20
		flags = append(flags, "DKIM firmado por '"+joinStrings(h.DKIMSigners)+"' ≠ '"+h.FromDomain+"' (misalignment)")
	}

	// Reply-To apunta a dominio diferente
	if h.ReplyToDiffers {
		score += 15
		flags = append(flags, "Reply-To apunta a dominio diferente al remitente")
	}

	// Soporte vía WhatsApp
	if len(r.Body.WhatsAppLinks) > 0 {
		score += 25
		flags = append(flags, "soporte vía WhatsApp: "+joinStrings(r.Body.WhatsAppLinks))
	}

	// Solicitud de transferencia bancaria
	if len(r.Body.BankAccounts) > 0 {
		score += 35
		flags = append(flags, "solicita transferencia a cuenta bancaria: "+joinStrings(r.Body.BankAccounts))
	}

	// Urgencia + amenazas
	if len(r.Body.UrgencyPhrases) >= 3 {
		score += 20
		flags = append(flags, "múltiples frases de urgencia/amenaza ("+itoa(len(r.Body.UrgencyPhrases))+" detectadas)")
	} else if len(r.Body.UrgencyPhrases) > 0 {
		score += 10
		flags = append(flags, "frases de urgencia: "+joinStrings(r.Body.UrgencyPhrases[:min(2, len(r.Body.UrgencyPhrases))]))
	}

	// Solicitud de datos de tarjeta (CVV, número, fecha) — nadie legítimo pide esto por email
	if len(r.Body.CreditCardRequests) > 0 {
		score += 50
		flags = append(flags, "solicita datos de tarjeta de crédito: "+joinStrings(r.Body.CreditCardRequests))
	}

	// Solicitud de documentos de identidad (INE, CURP, RFC)
	if len(r.Body.IdentityRequests) > 0 {
		score += 30
		flags = append(flags, "solicita documentos de identidad: "+joinStrings(r.Body.IdentityRequests))
	}

	// Rastreador personal en email supuestamente corporativo
	if len(r.Body.PersonalTrackers) > 0 {
		score += 15
		flags = append(flags, "rastreador personal en email 'oficial': "+joinStrings(r.Body.PersonalTrackers))
	}

	// Teléfono de país inconsistente
	if len(r.Body.ForeignPhones) > 0 {
		score += 15
		flags = append(flags, "teléfono de país inconsistente: "+joinStrings(r.Body.ForeignPhones))
	}

	// Links sospechosos en el cuerpo
	for _, lr := range r.LinkResults {
		switch lr.RiskLevel {
		case "CRITICO":
			score += 40
			flags = append(flags, "link CRITICO en el cuerpo: "+lr.URL+" — "+lr.TopFlag)
		case "ALTO":
			score += 25
			flags = append(flags, "link de alto riesgo en el cuerpo: "+lr.URL+" — "+lr.TopFlag)
		case "MEDIO":
			score += 10
			flags = append(flags, "link sospechoso en el cuerpo: "+lr.URL+" — "+lr.TopFlag)
		}
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

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
