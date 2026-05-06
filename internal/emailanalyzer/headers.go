package emailanalyzer

import (
	"strings"
)

type HeaderResult struct {
	FromDomain        string
	ImpersonatedBrand string   // marca que intenta imitar
	IsOfficialDomain  bool     // el from-domain ES el oficial
	DKIMSigners       []string // dominios que firmaron
	DKIMAligned       bool     // al menos un firmante == from-domain
	ReplyToDiffers    bool     // reply-to apunta a dominio diferente
}

func CheckHeaders(pe ParsedEmail) HeaderResult {
	result := HeaderResult{
		FromDomain: pe.FromDomain,
	}

	// Detectar qué marca intenta imitar el from-domain
	result.ImpersonatedBrand, result.IsOfficialDomain = detectImpersonation(pe.FromDomain)

	// Extraer dominios que firmaron DKIM
	result.DKIMSigners = extractDKIMSigners(pe.DKIMHeaders, pe.AuthResults)

	// DKIM alignment: algún firmante debe coincidir con el from-domain
	fromRoot := rootDomain(pe.FromDomain)
	for _, signer := range result.DKIMSigners {
		if rootDomain(signer) == fromRoot {
			result.DKIMAligned = true
			break
		}
	}

	// Reply-To en dominio diferente
	if pe.ReplyTo != "" {
		replyDomain := extractFromDomain(pe.ReplyTo)
		if replyDomain != "" && rootDomain(replyDomain) != fromRoot {
			result.ReplyToDiffers = true
		}
	}

	return result
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
