package emailanalyzer

import (
	"regexp"
	"strings"
)

type BodyResult struct {
	WhatsAppLinks       []string // wa.me links encontrados
	BankAccounts        []string // números de cuenta / CLABE detectados
	UrgencyPhrases      []string // frases de urgencia/amenaza
	PersonalTrackers    []string // rastreadores personales detectados
	ForeignPhones       []string // teléfonos de países inconsistentes
	SuspiciousLinks     []string // links a dominios distintos del remitente
	CreditCardRequests  []string // palabras clave de solicitud de datos de tarjeta
	IdentityRequests    []string // palabras clave de solicitud de documentos de identidad
}

var (
	reWhatsApp    = regexp.MustCompile(`https?://wa\.me/[+\d]+`)
	reCLABE       = regexp.MustCompile(`\b\d{18}\b`)                             // CLABE mexicana
	reBankAccount = regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{6,12}\b`)    // formato cuenta
	rePhone       = regexp.MustCompile(`\+\d{1,3}[\s\-]?\d[\d\s\-]{7,14}`)
	reLinks       = regexp.MustCompile(`https?://[^\s"'<>]+`)
)

func CheckBody(pe ParsedEmail, fromDomain string) BodyResult {
	result := BodyResult{}
	combined := pe.TextBody + " " + pe.HTMLBody
	lower := strings.ToLower(combined)

	// WhatsApp links — real marketplaces no usan wa.me para soporte
	result.WhatsAppLinks = reWhatsApp.FindAllString(combined, -1)

	// CLABE / números de cuenta bancaria
	for _, m := range reCLABE.FindAllString(combined, -1) {
		result.BankAccounts = append(result.BankAccounts, m+" (CLABE)")
	}
	for _, m := range reBankAccount.FindAllString(combined, -1) {
		if !containsString(result.BankAccounts, m) {
			result.BankAccounts = append(result.BankAccounts, m)
		}
	}

	// Frases de urgencia y amenaza (español e inglés)
	for _, kw := range urgencyKeywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			result.UrgencyPhrases = append(result.UrgencyPhrases, kw)
		}
	}
	for _, kw := range urgencyKeywordsEN {
		if strings.Contains(lower, strings.ToLower(kw)) {
			if !containsString(result.UrgencyPhrases, kw) {
				result.UrgencyPhrases = append(result.UrgencyPhrases, kw)
			}
		}
	}

	// Rastreadores personales
	for _, tracker := range personalTrackers {
		if strings.Contains(lower, tracker) {
			result.PersonalTrackers = append(result.PersonalTrackers, tracker)
		}
	}

	// Teléfonos con código de país sospechoso
	// (ej: +54 Argentina en email que imita MercadoLibre México)
	for _, phone := range rePhone.FindAllString(combined, -1) {
		if isForeignPhone(phone, fromDomain) {
			result.ForeignPhones = append(result.ForeignPhones, strings.TrimSpace(phone))
		}
	}

	// Solicitud de datos de tarjeta de crédito
	for _, kw := range creditCardKeywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			result.CreditCardRequests = append(result.CreditCardRequests, kw)
		}
	}

	// Solicitud de documentos de identidad
	for _, kw := range identityKeywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			result.IdentityRequests = append(result.IdentityRequests, kw)
		}
	}

	// Links que apuntan a dominios distintos del remitente
	fromRoot := rootDomain(fromDomain)
	for _, link := range reLinks.FindAllString(combined, -1) {
		linkDomain := extractLinkDomain(link)
		if linkDomain == "" {
			continue
		}
		linkRoot := rootDomain(linkDomain)
		// Excluir dominios oficiales conocidos y CDNs
		if linkRoot != fromRoot && !isKnownCDN(linkRoot) {
			if !containsString(result.SuspiciousLinks, link) {
				result.SuspiciousLinks = append(result.SuspiciousLinks, link)
			}
		}
	}

	return result
}

func isForeignPhone(phone, fromDomain string) bool {
	expected := expectedPhonePrefixes(fromDomain)
	if len(expected) == 0 {
		return false // dominio global (.com sin marca específica) — no se puede determinar
	}
	p := strings.TrimSpace(phone)
	for _, prefix := range expected {
		if strings.HasPrefix(p, prefix) {
			return false
		}
	}
	return true
}

func expectedPhonePrefixes(fromDomain string) []string {
	lower := strings.ToLower(fromDomain)

	// 1. Buscar por TLD de país — del más específico al más corto
	tlds := []string{
		".com.mx", ".com.br", ".com.co", ".com.ar", ".com.cl",
		".com.pe", ".com.ve", ".com.ec", ".com.es", ".com.au",
		".co.uk", ".mx", ".br", ".co", ".ar", ".cl", ".pe",
		".ve", ".ec", ".es", ".au", ".uk", ".de", ".fr", ".ca",
	}
	for _, tld := range tlds {
		if strings.HasSuffix(lower, tld) {
			if codes, ok := tldToPhonePrefix[tld]; ok {
				return codes
			}
		}
	}

	// 2. Buscar por marca conocida de país único (ej: liverpool.com → +52)
	for brand, codes := range brandToPhonePrefix {
		if strings.Contains(lower, brand) {
			return codes
		}
	}

	return nil
}

func extractLinkDomain(link string) string {
	link = strings.TrimPrefix(link, "https://")
	link = strings.TrimPrefix(link, "http://")
	parts := strings.SplitN(link, "/", 2)
	if len(parts) > 0 {
		return strings.ToLower(parts[0])
	}
	return ""
}

func isKnownCDN(domain string) bool {
	cdns := []string{
		"cloudfront.net", "amazonaws.com", "googleapis.com",
		"gstatic.com", "google.com", "facebook.com",
		"twitter.com", "instagram.com", "youtube.com",
		"mailtrack.io", "list-prefs.com", "s3.amazonaws.com",
		"wa.me", // WhatsApp — ya detectado por reWhatsApp
	}
	for _, cdn := range cdns {
		if strings.HasSuffix(domain, cdn) || domain == cdn {
			return true
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
