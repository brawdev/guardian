package emailanalyzer

import (
	"net/mail"
	"strings"
)

type HeaderResult struct {
	FromDomain          string      `json:"from_domain,omitempty"`
	DisplayName         string      `json:"display_name,omitempty"`
	DisplayNameSpoofing bool        `json:"display_name_spoofing,omitempty"`
	ImpersonatedBrand   string      `json:"impersonated_brand,omitempty"`
	IsOfficialDomain    bool        `json:"is_official_domain,omitempty"`
	DKIMSigners         []string    `json:"dkim_signers,omitempty"`
	DKIMAligned         bool        `json:"dkim_aligned,omitempty"`
	ReplyToDiffers      bool        `json:"reply_to_differs,omitempty"`
	SPF                 SPFResult   `json:"spf,omitempty"`
	DMARC               DMARCResult `json:"dmarc,omitempty"`
}

func CheckHeaders(pe ParsedEmail) HeaderResult {
	result := HeaderResult{
		FromDomain: pe.FromDomain,
	}

	result.ImpersonatedBrand, result.IsOfficialDomain = detectImpersonation(pe.FromDomain)
	result.DisplayName, result.DisplayNameSpoofing = detectDisplayNameSpoofing(pe.From, pe.FromDomain)
	result.DKIMSigners = extractDKIMSigners(pe.DKIMHeaders, pe.AuthResults)

	fromRoot := rootDomain(pe.FromDomain)
	for _, signer := range result.DKIMSigners {
		if rootDomain(signer) == fromRoot {
			result.DKIMAligned = true
			break
		}
	}

	if pe.ReplyTo != "" {
		replyDomain := extractFromDomain(pe.ReplyTo)
		if replyDomain != "" && rootDomain(replyDomain) != fromRoot {
			result.ReplyToDiffers = true
		}
	}

	// SPF y DMARC en paralelo
	spfCh := make(chan SPFResult, 1)
	dmarcCh := make(chan DMARCResult, 1)
	go func() { spfCh <- CheckSPF(pe.FromDomain) }()
	go func() { dmarcCh <- CheckDMARC(pe.FromDomain) }()
	result.SPF = <-spfCh
	result.DMARC = <-dmarcCh

	return result
}

func detectDisplayNameSpoofing(from, fromDomain string) (displayName string, spoofing bool) {
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return "", false
	}
	displayName = addr.Name
	if displayName == "" {
		return "", false
	}

	lowerName := strings.ToLower(displayName)
	for brandName, officialDomains := range officialSenderDomains {
		if !strings.Contains(lowerName, brandName) {
			continue
		}
		// El display name menciona la marca — verificar si el dominio es oficial
		isOfficial := false
		for _, od := range officialDomains {
			if strings.ToLower(fromDomain) == od {
				isOfficial = true
				break
			}
		}
		if !isOfficial {
			return displayName, true
		}
	}
	return displayName, false
}

func detectImpersonation(domain string) (brand string, isOfficial bool) {
	domain = strings.ToLower(domain)
	for brandName, officialDomains := range officialSenderDomains {
		for _, od := range officialDomains {
			if domain == od {
				return brandName, true
			}
		}
		// El dominio contiene la marca pero no es oficial
		if strings.Contains(domain, brandName) {
			return brandName, false
		}
	}
	return "", false
}

func extractDKIMSigners(dkimHeaders []string, authResults string) []string {
	seen := map[string]bool{}
	var signers []string

	// Parsear headers DKIM-Signature: buscar d= tag
	for _, h := range dkimHeaders {
		for _, part := range strings.Split(h, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "d=") {
				d := strings.TrimPrefix(part, "d=")
				d = strings.TrimSpace(d)
				if d != "" && !seen[d] {
					seen[d] = true
					signers = append(signers, d)
				}
			}
		}
	}

	// También extraer de Authentication-Results: dkim=pass header.i=@domain
	for _, line := range strings.Split(authResults, ";") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "dkim=pass") {
			if idx := strings.Index(line, "header.i=@"); idx != -1 {
				d := strings.TrimPrefix(line[idx:], "header.i=@")
				d = strings.Fields(d)[0]
				if !seen[d] {
					seen[d] = true
					signers = append(signers, d)
				}
			}
		}
	}

	return signers
}

func rootDomain(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}
