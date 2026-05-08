package phoneanalyzer

import (
	"regexp"
	"strings"
)

type Result struct {
	Input          string   `json:"input,omitempty"`
	Normalized     string   `json:"normalized,omitempty"`
	CountryCode    string   `json:"country_code,omitempty"`
	CountryName    string   `json:"country_name,omitempty"`
	IsValid        bool     `json:"is_valid,omitempty"`
	IsVoIP         bool     `json:"is_voip,omitempty"`
	VoIPProvider   string   `json:"voip_provider,omitempty"`
	RiskScore      int      `json:"risk_score,omitempty"`
	RiskLevel      string   `json:"risk_level,omitempty"`
	Flags          []string `json:"flags,omitempty"`
}

var reDigits = regexp.MustCompile(`\D`)

func Analyze(phone, countryContext string) Result {
	result := Result{Input: phone}

	normalized := normalize(phone)
	if normalized == "" {
		result.Flags = append(result.Flags, "número no válido o vacío")
		result.RiskLevel = "BAJO"
		return result
	}
	result.Normalized = normalized

	// Detectar código de país
	result.CountryCode, result.CountryName = detectCountry(normalized)
	result.IsValid = result.CountryCode != ""

	if !result.IsValid {
		result.Flags = append(result.Flags, "no se reconoce el código de país")
	}

	// Detectar rangos VoIP conocidos
	result.IsVoIP, result.VoIPProvider = detectVoIP(normalized)

	// Calcular riesgo
	result.RiskScore, result.Flags = calculateRisk(result, countryContext)
	result.RiskLevel = scoreToLevel(result.RiskScore)

	return result
}

func normalize(phone string) string {
	digits := reDigits.ReplaceAllString(phone, "")
	if len(digits) < 7 {
		return ""
	}
	if strings.HasPrefix(phone, "+") {
		return "+" + digits
	}
	if strings.HasPrefix(digits, "00") {
		return "+" + digits[2:]
	}
	return digits
}

func detectCountry(normalized string) (code, name string) {
	for prefix, info := range countryPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return prefix, info
		}
	}
	return "", ""
}

func detectVoIP(normalized string) (bool, string) {
	for _, r := range voipRanges {
		if strings.HasPrefix(normalized, r.prefix) {
			return true, r.provider
		}
	}
	return false, ""
}

func calculateRisk(r Result, countryContext string) (int, []string) {
	score := 0
	var flags []string

	if !r.IsValid {
		score += 15
		flags = append(flags, "formato de número inválido o no reconocido")
	}

	if r.IsVoIP {
		score += 40
		flags = append(flags, "número VoIP ("+r.VoIPProvider+") — frecuentemente usado en fraude telefónico")
	}

	// País del número inconsistente con contexto
	if countryContext != "" && r.CountryCode != "" {
		expectedCode := countryContextToPrefix(countryContext)
		if expectedCode != "" && !strings.HasPrefix(r.CountryCode, expectedCode) {
			score += 25
			flags = append(flags, "número de "+r.CountryName+" en contexto de '"+countryContext+"'")
		}
	}

	if score > 100 {
		score = 100
	}
	return score, flags
}

func countryContextToPrefix(context string) string {
	m := map[string]string{
		"MX": "+52", "mexico": "+52", "mx": "+52",
		"US": "+1", "usa": "+1", "us": "+1",
		"BR": "+55", "brasil": "+55", "br": "+55",
		"AR": "+54", "argentina": "+54", "ar": "+54",
		"CO": "+57", "colombia": "+57", "co": "+57",
		"CL": "+56", "chile": "+56", "cl": "+56",
		"PE": "+51", "peru": "+51", "pe": "+51",
		"ES": "+34", "españa": "+34", "es": "+34",
	}
	return m[strings.ToLower(context)]
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
