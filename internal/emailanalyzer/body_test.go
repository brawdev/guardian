package emailanalyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckBody_WhatsApp(t *testing.T) {
	pe := ParsedEmail{TextBody: "Contacta soporte: https://wa.me/+5212345678901"}
	result := CheckBody(pe, "infomercadolibre.com")
	assert.NotEmpty(t, result.WhatsAppLinks)
	assert.Contains(t, result.WhatsAppLinks[0], "wa.me")
}

func TestCheckBody_BankAccount(t *testing.T) {
	t.Run("CLABE 18 dígitos", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Deposita a: 012345678901234567"}
		result := CheckBody(pe, "test.com")
		assert.NotEmpty(t, result.BankAccounts)
		assert.Contains(t, result.BankAccounts[0], "CLABE")
	})

	t.Run("formato cuenta con guiones", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Cuenta: 0087-6676-011032629274"}
		result := CheckBody(pe, "test.com")
		assert.NotEmpty(t, result.BankAccounts)
	})

	t.Run("sin cuenta bancaria", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Gracias por tu compra"}
		result := CheckBody(pe, "test.com")
		assert.Empty(t, result.BankAccounts)
	})
}

func TestCheckBody_UrgencyKeywords(t *testing.T) {
	t.Run("múltiples frases de urgencia", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Tienes 12 horas o será bloqueado. Procede con el envío inmediatamente."}
		result := CheckBody(pe, "test.com")
		assert.GreaterOrEqual(t, len(result.UrgencyPhrases), 2)
	})

	t.Run("pago pausado y mantenimiento rutinario", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Tu pago ha sido pausado por mantenimiento rutinario."}
		result := CheckBody(pe, "test.com")
		assert.GreaterOrEqual(t, len(result.UrgencyPhrases), 2)
	})

	t.Run("sin frases de urgencia", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Gracias por tu compra. Tu pedido llegará en 3 días."}
		result := CheckBody(pe, "test.com")
		assert.Empty(t, result.UrgencyPhrases)
	})
}

func TestCheckBody_CreditCardKeywords(t *testing.T) {
	t.Run("CVV y número de tarjeta", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Proporciona tu CVV y número de tarjeta para verificar."}
		result := CheckBody(pe, "test.com")
		assert.NotEmpty(t, result.CreditCardRequests)
	})

	t.Run("fecha de vencimiento", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Ingresa la fecha de vencimiento de tu tarjeta de crédito."}
		result := CheckBody(pe, "test.com")
		assert.NotEmpty(t, result.CreditCardRequests)
	})

	t.Run("sin solicitud de tarjeta", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Tu pago fue recibido correctamente."}
		result := CheckBody(pe, "test.com")
		assert.Empty(t, result.CreditCardRequests)
	})
}

func TestCheckBody_IdentityKeywords(t *testing.T) {
	t.Run("CURP solicitado", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Proporciona tu CURP para verificación."}
		result := CheckBody(pe, "test.com")
		assert.NotEmpty(t, result.IdentityRequests)
	})

	t.Run("número de INE", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Envía tu número de INE y RFC."}
		result := CheckBody(pe, "test.com")
		assert.GreaterOrEqual(t, len(result.IdentityRequests), 2)
	})

	t.Run("sin solicitud de identidad", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Confirma tu dirección de envío."}
		result := CheckBody(pe, "test.com")
		assert.Empty(t, result.IdentityRequests)
	})
}

func TestCheckBody_PersonalTrackers(t *testing.T) {
	t.Run("mailtrack.io detectado", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Confirmación https://mailtrack.io/trace/mail/abc123.png?u=999"}
		result := CheckBody(pe, "mercadolibre.com")
		assert.NotEmpty(t, result.PersonalTrackers)
		assert.Contains(t, result.PersonalTrackers, "mailtrack.io")
	})

	t.Run("mailsuite detectado", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Ver detalles con mailsuite tracker incluido"}
		result := CheckBody(pe, "mercadolibre.com")
		assert.NotEmpty(t, result.PersonalTrackers)
	})

	t.Run("sin rastreadores", func(t *testing.T) {
		pe := ParsedEmail{TextBody: "Tu pedido ha sido enviado."}
		result := CheckBody(pe, "mercadolibre.com")
		assert.Empty(t, result.PersonalTrackers)
	})
}

func TestExpectedPhonePrefixes(t *testing.T) {
	t.Run("dominios con TLD de país", func(t *testing.T) {
		cases := []struct {
			domain string
			prefix string
		}{
			{"tienda.com.mx", "+52"},
			{"loja.com.br", "+55"},
			{"tienda.com.co", "+57"},
			{"tienda.com.ar", "+54"},
			{"tienda.com.cl", "+56"},
		}
		for _, tc := range cases {
			prefixes := expectedPhonePrefixes(tc.domain)
			assert.NotEmpty(t, prefixes, tc.domain)
			assert.Equal(t, tc.prefix, prefixes[0], tc.domain)
		}
	})

	t.Run("marcas con mercado definido", func(t *testing.T) {
		prefixes := expectedPhonePrefixes("liverpool.com")
		assert.NotEmpty(t, prefixes)
		assert.Equal(t, "+52", prefixes[0])
	})

	t.Run("marcas globales — no determinable", func(t *testing.T) {
		assert.Nil(t, expectedPhonePrefixes("amazon.com"))
		assert.Nil(t, expectedPhonePrefixes("shein.com"))
	})
}

func TestIsForeignPhone(t *testing.T) {
	t.Run("México en dominio .mx — no sospechoso", func(t *testing.T) {
		assert.False(t, isForeignPhone("+5212345678901", "tienda.com.mx"))
	})

	t.Run("Argentina en dominio .mx — sospechoso", func(t *testing.T) {
		assert.True(t, isForeignPhone("+5491176499251", "tienda.com.mx"))
	})

	t.Run("China en dominio .mx — sospechoso", func(t *testing.T) {
		assert.True(t, isForeignPhone("+8613912345678", "shein-soporte.com.mx"))
	})

	t.Run("cualquier número en Amazon global — no determinable", func(t *testing.T) {
		assert.False(t, isForeignPhone("+8613912345678", "amazon.com"))
	})

	t.Run("México en Liverpool — no sospechoso", func(t *testing.T) {
		assert.False(t, isForeignPhone("+5212345678901", "liverpool.com"))
	})

	t.Run("Argentina en Liverpool — sospechoso", func(t *testing.T) {
		assert.True(t, isForeignPhone("+5491176499251", "liverpool.com"))
	})
}
