package emailanalyzer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func containsSubstring(flags []string, sub string) bool {
	for _, f := range flags {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestCalculateRisk_ScoreCritico(t *testing.T) {
	r := Result{
		Headers: HeaderResult{
			FromDomain:        "infomercadolibre.com",
			ImpersonatedBrand: "mercadolibre",
			IsOfficialDomain:  false,
			DKIMSigners:       []string{"oxsus-vadesecure.net"},
			DKIMAligned:       false,
		},
		Body: BodyResult{
			WhatsAppLinks:  []string{"https://wa.me/+5491176499251"},
			BankAccounts:   []string{"0087-6676-011032629274"},
			UrgencyPhrases: []string{"12 horas", "será bloqueado", "procede con el envío"},
		},
	}

	score, flags := calculateRisk(r)

	assert.GreaterOrEqual(t, score, 75, "debe ser CRITICO con estas señales")
	assert.NotEmpty(t, flags)
}

func TestCalculateRisk_ScoreBajo(t *testing.T) {
	r := Result{
		Headers: HeaderResult{
			FromDomain:       "mercadolibre.com",
			IsOfficialDomain: true,
			DKIMAligned:      true,
			SPF:              SPFResult{HasRecord: true, Policy: "-all", IsStrict: true},
			DMARC:            DMARCResult{HasRecord: true, Policy: "reject", IsStrict: true},
		},
		Body: BodyResult{},
	}

	score, flags := calculateRisk(r)

	assert.Equal(t, 0, score)
	assert.Empty(t, flags)
}

func TestCalculateRisk_TarjetaCredito(t *testing.T) {
	r := Result{
		Body: BodyResult{
			CreditCardRequests: []string{"cvv", "número de tarjeta"},
		},
	}

	score, flags := calculateRisk(r)

	assert.GreaterOrEqual(t, score, 50, "solicitud de CVV debe ser ALTO por sí sola")
	assert.NotEmpty(t, flags)
	assert.True(t, containsSubstring(flags, "tarjeta"), "debe haber un flag sobre tarjeta")
}

func TestCalculateRisk_DocumentosIdentidad(t *testing.T) {
	r := Result{
		Body: BodyResult{
			IdentityRequests: []string{"curp", "rfc"},
		},
	}

	score, flags := calculateRisk(r)

	assert.GreaterOrEqual(t, score, 25)
	assert.NotEmpty(t, flags)
	assert.True(t, containsSubstring(flags, "identidad"), "debe haber un flag sobre identidad")
}

func TestCalculateRisk_NoCap100(t *testing.T) {
	// Todas las señales activas — no debe superar 100
	r := Result{
		Headers: HeaderResult{
			ImpersonatedBrand: "mercadolibre",
			IsOfficialDomain:  false,
			DKIMSigners:       []string{"spammer.net"},
			DKIMAligned:       false,
			ReplyToDiffers:    true,
		},
		Body: BodyResult{
			WhatsAppLinks:      []string{"https://wa.me/+54911"},
			BankAccounts:       []string{"123456789012345678"},
			UrgencyPhrases:     []string{"1", "2", "3"},
			CreditCardRequests: []string{"cvv"},
			IdentityRequests:   []string{"curp"},
			PersonalTrackers:   []string{"mailtrack.io"},
			ForeignPhones:      []string{"+54911"},
		},
	}

	score, _ := calculateRisk(r)
	assert.Equal(t, 100, score, "el score no debe superar 100")
}

func TestScoreToLevel(t *testing.T) {
	assert.Equal(t, "CRITICO", scoreToLevel(100))
	assert.Equal(t, "CRITICO", scoreToLevel(75))
	assert.Equal(t, "ALTO", scoreToLevel(74))
	assert.Equal(t, "ALTO", scoreToLevel(50))
	assert.Equal(t, "MEDIO", scoreToLevel(49))
	assert.Equal(t, "MEDIO", scoreToLevel(25))
	assert.Equal(t, "BAJO", scoreToLevel(24))
	assert.Equal(t, "BAJO", scoreToLevel(0))
}
