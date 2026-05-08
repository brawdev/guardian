package urlanalyzer

import (
	"strings"

	"github.com/agnivade/levenshtein"
	"golang.org/x/net/idna"
)

type TypoResult struct {
	IsTyposquat   bool   `json:"is_typosquat,omitempty"`
	ClosestBrand  string `json:"closest_brand,omitempty"`
	Distance      int    `json:"distance,omitempty"`
	Suspicious    string `json:"suspicious,omitempty"`
	ContainsBrand bool   `json:"contains_brand,omitempty"`
	MatchType     string `json:"match_type,omitempty"`
	IsPunycode    bool   `json:"is_punycode,omitempty"`
	DecodedDomain string `json:"decoded_domain,omitempty"`
}

// homoglyphs mapeo de caracteres visualmente similares usados en ataques
var homoglyphs = map[rune]rune{
	'0': 'o', '1': 'l', '3': 'e', '4': 'a',
	'5': 's', '6': 'g', '7': 't', '8': 'b',
	'@': 'a', '!': 'i', '$': 's',
}

func normalizeHomoglyphs(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if replacement, ok := homoglyphs[r]; ok {
			b.WriteRune(replacement)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func CheckTyposquatting(hostname string) TypoResult {
	// Detectar y decodificar dominios Punycode/IDN (xn--)
	// ej: xn--mercadolbre-q1b.com → mercadolíbre.com
	if strings.Contains(strings.ToLower(hostname), "xn--") {
		decoded, err := idna.ToUnicode(hostname)
		if err == nil && decoded != hostname {
			result := CheckTyposquatting(decoded)
			result.IsPunycode = true
			result.DecodedDomain = decoded
			return result
		}
	}

	clean := stripTLD(strings.ToLower(hostname))
	clean = strings.TrimPrefix(clean, "www.")

	// Paso 1: brand containment — el dominio contiene la marca exacta como substring
	// pero no ES la marca (ej: infomercadolibre, amazon-descuentos, pagos-paypal)
	for _, brand := range knownBrands {
		if strings.Contains(clean, brand) && clean != brand {
			return TypoResult{
				IsTyposquat:   true,
				ContainsBrand: true,
				ClosestBrand:  brand,
				Distance:      0,
				Suspicious:    clean,
				MatchType:     "contains",
			}
		}
	}

	// Paso 2: Levenshtein por segmentos (amaz0n, mercad0libre)
	candidates := []string{clean}
	for _, seg := range strings.Split(clean, "-") {
		if len(seg) >= 4 {
			candidates = append(candidates, seg)
		}
	}

	best := TypoResult{Distance: 999}

	for _, candidate := range candidates {
		normalized := normalizeHomoglyphs(candidate)
		for _, brand := range knownBrands {
			d := levenshtein.ComputeDistance(candidate, brand)
			if d < best.Distance {
				best = TypoResult{Distance: d, ClosestBrand: brand, Suspicious: candidate, MatchType: "levenshtein"}
			}
			dn := levenshtein.ComputeDistance(normalized, brand)
			if dn < best.Distance {
				best = TypoResult{Distance: dn, ClosestBrand: brand, Suspicious: candidate, MatchType: "homoglyph"}
			}
		}
	}

	best.IsTyposquat = best.Distance >= 0 && best.Distance <= 2 && best.Suspicious != best.ClosestBrand
	return best
}

func stripTLD(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		// Maneja ccTLD dobles como .com.mx, .co.uk
		if len(parts) >= 3 && len(parts[len(parts)-2]) <= 3 {
			return strings.Join(parts[:len(parts)-2], ".")
		}
		return strings.Join(parts[:len(parts)-1], ".")
	}
	return hostname
}
