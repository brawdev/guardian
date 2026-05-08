package emailanalyzer

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type HiddenLink struct {
	DisplayText string `json:"display_text,omitempty"`
	ActualURL   string `json:"actual_url,omitempty"`
}

type BodyResult struct {
	WhatsAppLinks      []string     `json:"whatsapp_links,omitempty"`
	BankAccounts       []string     `json:"bank_accounts,omitempty"`
	UrgencyPhrases     []string     `json:"urgency_phrases,omitempty"`
	PersonalTrackers   []string     `json:"personal_trackers,omitempty"`
	AllPhones          []string     `json:"all_phones,omitempty"`
	ForeignPhones      []string     `json:"foreign_phones,omitempty"`
	SuspiciousLinks    []string     `json:"suspicious_links,omitempty"`
	HiddenLinks        []HiddenLink `json:"hidden_links,omitempty"`
	CreditCardRequests []string     `json:"credit_card_requests,omitempty"`
	IdentityRequests   []string     `json:"identity_requests,omitempty"`
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

	// Todos los teléfonos detectados + clasificación de extranjeros
	for _, phone := range rePhone.FindAllString(combined, -1) {
		phone = strings.TrimSpace(phone)
		if !containsString(result.AllPhones, phone) {
			result.AllPhones = append(result.AllPhones, phone)
		}
		if isForeignPhone(phone, fromDomain) && !containsString(result.ForeignPhones, phone) {
			result.ForeignPhones = append(result.ForeignPhones, phone)
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
		if linkRoot != fromRoot && !isKnownCDN(linkRoot) {
			if !containsString(result.SuspiciousLinks, link) {
				result.SuspiciousLinks = append(result.SuspiciousLinks, link)
			}
		}
	}

	// Links ocultos en HTML: texto visible ≠ href real
	result.HiddenLinks = findHiddenLinks(pe.HTMLBody)

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

func findHiddenLinks(htmlBody string) []HiddenLink {
	if htmlBody == "" {
		return nil
	}
	doc, err := html.Parse(strings.NewReader(htmlBody))
	if err != nil {
		return nil
	}

	var results []HiddenLink
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			var href string
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					href = strings.TrimSpace(attr.Val)
					break
				}
			}
			if href == "" || !strings.HasPrefix(href, "http") {
				goto next
			}

			// Extraer texto visible del enlace
			var textBuf strings.Builder
			var extractText func(*html.Node)
			extractText = func(n *html.Node) {
				if n.Type == html.TextNode {
					textBuf.WriteString(n.Data)
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					extractText(c)
				}
			}
			extractText(n)
			displayText := strings.TrimSpace(textBuf.String())

			// Si el texto visible parece una URL o dominio diferente al href
			if looksLikeURL(displayText) {
				hrefDomain := rootDomain(extractLinkDomain(href))
				displayDomain := rootDomain(extractLinkDomain(displayText))
				if displayDomain != "" && hrefDomain != displayDomain {
					results = append(results, HiddenLink{
						DisplayText: displayText,
						ActualURL:   href,
					})
				}
			}
		}
	next:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return results
}

func looksLikeURL(s string) bool {
	s = strings.ToLower(s)
	return strings.HasPrefix(s, "http") || strings.Contains(s, ".com") ||
		strings.Contains(s, ".mx") || strings.Contains(s, ".net") ||
		strings.Contains(s, ".org") || strings.Contains(s, ".io")
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
