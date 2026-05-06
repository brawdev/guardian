package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/brawdev/guardian/internal/emailanalyzer"
	"github.com/brawdev/guardian/internal/urlanalyzer"
	"github.com/fatih/color"
)

func PrintURL(result urlanalyzer.Result, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}

	printHeader("ANÁLISIS DE URL")
	fmt.Printf("  URL:      %s\n", result.URL)
	fmt.Printf("  Dominio:  %s\n", result.Hostname)
	fmt.Println()

	levelColor := levelFn(result.RiskLevel)
	fmt.Printf("  Riesgo:   %s  (%d/100)\n", levelColor(result.RiskLevel), result.RiskScore)
	fmt.Println()

	printSection("CHECKS")

	// Typosquatting
	if result.Typo.IsTyposquat {
		var typoDetail string
		switch result.Typo.MatchType {
		case "contains":
			typoDetail = fmt.Sprintf("contiene la marca '%s' en el dominio", result.Typo.ClosestBrand)
		case "homoglyph":
			typoDetail = fmt.Sprintf("homoglifo de '%s' (ej: 0→o, 1→l)", result.Typo.ClosestBrand)
		default:
			typoDetail = fmt.Sprintf("similar a '%s' (distancia %d)", result.Typo.ClosestBrand, result.Typo.Distance)
		}
		warn("  Typosquatting", typoDetail)
	} else {
		ok("  Typosquatting", "sin coincidencias sospechosas")
	}

	// WHOIS
	if result.Whois.Error != "" {
		info("  WHOIS", "no disponible: "+result.Whois.Error)
	} else if result.Whois.IsNew {
		warn("  WHOIS", fmt.Sprintf("dominio creado %s (%d días)", result.Whois.CreatedDate, result.Whois.DomainAge))
	} else {
		ok("  WHOIS", fmt.Sprintf("dominio creado %s (%d días)", result.Whois.CreatedDate, result.Whois.DomainAge))
	}

	// TLS
	if !result.Redirects.TLSValid {
		danger("  SSL/TLS", "inválido o autofirmado")
	} else if result.Redirects.TLSIssuer != "" {
		ok("  SSL/TLS", "válido — emisor: "+result.Redirects.TLSIssuer)
	} else {
		ok("  SSL/TLS", "válido")
	}

	// Redirecciones
	if result.Redirects.CrossDomain {
		warn("  Redirecciones", fmt.Sprintf("%d hops — cambia de dominio", result.Redirects.HopCount))
	} else if result.Redirects.HopCount > 0 {
		info("  Redirecciones", fmt.Sprintf("%d hops → %s", result.Redirects.HopCount, result.Redirects.FinalURL))
	} else {
		ok("  Redirecciones", "sin redirecciones")
	}

	// Safe Browsing
	sb := result.Reputation.SafeBrowsing
	if sb.Error != "" {
		info("  Safe Browsing", "error: "+sb.Error)
	} else if sb.IsMalicious {
		danger("  Safe Browsing", "MALICIOSO — "+strings.Join(sb.ThreatTypes, ", "))
	} else {
		ok("  Safe Browsing", "limpio")
	}

	// VirusTotal
	vt := result.Reputation.VirusTotal
	if vt.Error != "" {
		info("  VirusTotal", vt.Error)
	} else if vt.IsMalicious {
		danger("  VirusTotal", fmt.Sprintf("%d/%d engines — %s", vt.Malicious, vt.TotalEngines, urlanalyzer.VTVendorSummary(vt.Vendors)))
	} else if vt.Suspicious > 0 {
		warn("  VirusTotal", fmt.Sprintf("%d engines sospechoso", vt.Suspicious))
	} else if vt.TotalEngines > 0 {
		ok("  VirusTotal", fmt.Sprintf("limpio (%d engines)", vt.TotalEngines))
	}

	// Flags resumen
	if len(result.Flags) > 0 {
		fmt.Println()
		printSection("SEÑALES DE ALERTA")
		for _, f := range result.Flags {
			fmt.Printf("  %s %s\n", color.YellowString("⚠"), f)
		}
	}

	fmt.Println()
}

func printHeader(title string) {
	line := strings.Repeat("─", 50)
	color.New(color.FgCyan, color.Bold).Printf("\n  %s\n", title)
	fmt.Printf("  %s\n", line)
}

func printSection(title string) {
	color.New(color.FgWhite, color.Bold).Printf("  %s\n", title)
}

func ok(label, msg string) {
	fmt.Printf("  %s %-18s %s\n", color.GreenString("✓"), label, msg)
}

func warn(label, msg string) {
	fmt.Printf("  %s %-18s %s\n", color.YellowString("⚠"), label, color.YellowString(msg))
}

func danger(label, msg string) {
	fmt.Printf("  %s %-18s %s\n", color.RedString("✗"), label, color.RedString(msg))
}

func info(label, msg string) {
	fmt.Printf("  %s %-18s %s\n", color.BlueString("i"), label, msg)
}

func levelFn(level string) func(string, ...interface{}) string {
	switch level {
	case "CRITICO":
		return color.New(color.FgRed, color.Bold).SprintfFunc()
	case "ALTO":
		return color.New(color.FgRed).SprintfFunc()
	case "MEDIO":
		return color.New(color.FgYellow).SprintfFunc()
	default:
		return color.New(color.FgGreen).SprintfFunc()
	}
}

func PrintEmail(result emailanalyzer.Result, asJSON bool) {
	if asJSON {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}

	printHeader("ANÁLISIS DE EMAIL")
	if result.File == "-" {
		fmt.Printf("  Fuente:  stdin (texto pegado)\n")
	} else {
		fmt.Printf("  Archivo: %s\n", result.File)
	}
	if result.From != "" {
		fmt.Printf("  De:      %s\n", result.From)
	}
	if result.Subject != "" {
		fmt.Printf("  Asunto:  %s\n", result.Subject)
	}
	fmt.Println()

	levelColor := levelFn(result.RiskLevel)
	fmt.Printf("  Riesgo:  %s  (%d/100)\n", levelColor(result.RiskLevel), result.RiskScore)
	fmt.Println()

	if result.HeadersAvailable {
		printSection("CHECKS DE CABECERAS")

		h := result.Headers
		if h.ImpersonatedBrand != "" && !h.IsOfficialDomain {
			danger("  From domain", "'"+h.FromDomain+"' suplanta a '"+h.ImpersonatedBrand+"'")
		} else if h.IsOfficialDomain {
			ok("  From domain", h.FromDomain+" (dominio oficial)")
		} else {
			info("  From domain", h.FromDomain)
		}

		if len(h.DKIMSigners) == 0 {
			danger("  DKIM", "sin firma DKIM")
		} else if !h.DKIMAligned {
			warn("  DKIM", "firmado por '"+strings.Join(h.DKIMSigners, ", ")+"' — no alineado con from-domain")
		} else {
			ok("  DKIM", "alineado ("+strings.Join(h.DKIMSigners, ", ")+")")
		}

		if h.ReplyToDiffers {
			warn("  Reply-To", "apunta a dominio diferente al remitente")
		} else {
			ok("  Reply-To", "consistente")
		}

		fmt.Println()
	} else {
		info("  Cabeceras", "no disponibles — análisis limitado al contenido del texto")
		fmt.Println()
	}
	printSection("CHECKS DE CONTENIDO")

	b := result.Body

	if len(b.WhatsAppLinks) > 0 {
		danger("  Soporte", "vía WhatsApp: "+strings.Join(b.WhatsAppLinks, ", "))
	} else {
		ok("  Soporte", "sin links a WhatsApp")
	}

	if len(b.BankAccounts) > 0 {
		danger("  Cuenta bancaria", strings.Join(b.BankAccounts, " | "))
	} else {
		ok("  Cuenta bancaria", "sin solicitudes de transferencia")
	}

	if len(b.UrgencyPhrases) >= 3 {
		danger("  Urgencia/amenaza", fmt.Sprintf("%d frases detectadas", len(b.UrgencyPhrases)))
	} else if len(b.UrgencyPhrases) > 0 {
		warn("  Urgencia/amenaza", strings.Join(b.UrgencyPhrases[:min(2, len(b.UrgencyPhrases))], "; "))
	} else {
		ok("  Urgencia/amenaza", "sin patrones detectados")
	}

	if len(b.CreditCardRequests) > 0 {
		danger("  Tarjeta crédito", fmt.Sprintf("%d señales: %s", len(b.CreditCardRequests), strings.Join(b.CreditCardRequests[:min(3, len(b.CreditCardRequests))], ", ")))
	} else {
		ok("  Tarjeta crédito", "sin solicitudes de datos de tarjeta")
	}

	if len(b.IdentityRequests) > 0 {
		danger("  Docs identidad", fmt.Sprintf("%d señales: %s", len(b.IdentityRequests), strings.Join(b.IdentityRequests[:min(3, len(b.IdentityRequests))], ", ")))
	} else {
		ok("  Docs identidad", "sin solicitudes de documentos")
	}

	if len(b.PersonalTrackers) > 0 {
		warn("  Email tracker", strings.Join(b.PersonalTrackers, ", ")+" (rastreador personal en email 'oficial')")
	} else {
		ok("  Email tracker", "sin rastreadores personales")
	}

	if len(b.ForeignPhones) > 0 {
		warn("  Teléfonos", "país inconsistente: "+strings.Join(b.ForeignPhones, ", "))
	} else {
		ok("  Teléfonos", "sin inconsistencias de país")
	}

	if len(result.LinkResults) > 0 {
		fmt.Println()
		printSection("LINKS EN EL CUERPO")
		for _, lr := range result.LinkResults {
			display := lr.URL
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			detail := fmt.Sprintf("%-8s (%d/100)", lr.RiskLevel, lr.RiskScore)
			if lr.TopFlag != "" {
				detail += " — " + lr.TopFlag
			}
			switch lr.RiskLevel {
			case "CRITICO", "ALTO":
				danger("  "+display, detail)
			case "MEDIO":
				warn("  "+display, detail)
			default:
				ok("  "+display, detail)
			}
		}
	}

	if len(result.Flags) > 0 {
		fmt.Println()
		printSection("SEÑALES DE ALERTA")
		for _, f := range result.Flags {
			fmt.Printf("  %s %s\n", color.RedString("✗"), f)
		}
	}

	fmt.Println()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
