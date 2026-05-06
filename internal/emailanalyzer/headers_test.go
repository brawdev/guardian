package emailanalyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectImpersonation(t *testing.T) {
	t.Run("dominio oficial — no es suplantación", func(t *testing.T) {
		brand, isOfficial := detectImpersonation("mercadolibre.com")
		assert.Equal(t, "mercadolibre", brand)
		assert.True(t, isOfficial)
	})

	t.Run("dominio falso que contiene la marca", func(t *testing.T) {
		brand, isOfficial := detectImpersonation("infomercadolibre.com")
		assert.Equal(t, "mercadolibre", brand)
		assert.False(t, isOfficial)
	})

	t.Run("Amazon oficial", func(t *testing.T) {
		brand, isOfficial := detectImpersonation("amazon.com")
		assert.Equal(t, "amazon", brand)
		assert.True(t, isOfficial)
	})

	t.Run("Amazon falso", func(t *testing.T) {
		brand, isOfficial := detectImpersonation("amazon-notification.com")
		assert.Equal(t, "amazon", brand)
		assert.False(t, isOfficial)
	})

	t.Run("dominio sin relación con marcas conocidas", func(t *testing.T) {
		brand, isOfficial := detectImpersonation("randomsite.com")
		assert.Empty(t, brand)
		assert.False(t, isOfficial)
	})
}

func TestExtractDKIMSigners(t *testing.T) {
	t.Run("extrae d= de DKIM-Signature header", func(t *testing.T) {
		headers := []string{"v=1; a=rsa-sha256; d=oxsus-vadesecure.net; s=key1; b=xxx"}
		signers := extractDKIMSigners(headers, "")
		assert.Contains(t, signers, "oxsus-vadesecure.net")
	})

	t.Run("extrae de Authentication-Results", func(t *testing.T) {
		authResults := "mx.google.com; dkim=pass header.i=@oxsus-vadesecure.net header.s=key1"
		signers := extractDKIMSigners(nil, authResults)
		assert.Contains(t, signers, "oxsus-vadesecure.net")
	})

	t.Run("sin firma DKIM", func(t *testing.T) {
		signers := extractDKIMSigners(nil, "")
		assert.Empty(t, signers)
	})

	t.Run("no duplica el mismo firmante", func(t *testing.T) {
		headers := []string{"d=mercadolibre.com; s=key1", "d=mercadolibre.com; s=key2"}
		signers := extractDKIMSigners(headers, "")
		assert.Len(t, signers, 1)
	})
}

func TestCheckHeaders_DKIMAlignment(t *testing.T) {
	t.Run("DKIM alineado — firmante coincide con from-domain", func(t *testing.T) {
		pe := ParsedEmail{
			From:        "MercadoLibre <notificacion@mercadolibre.com>",
			FromDomain:  "mercadolibre.com",
			DKIMHeaders: []string{"v=1; d=mercadolibre.com; s=key1; b=xxx"},
		}
		result := CheckHeaders(pe)
		assert.True(t, result.DKIMAligned)
	})

	t.Run("DKIM no alineado — firmante diferente al from-domain", func(t *testing.T) {
		pe := ParsedEmail{
			From:        "MercadoLibre <notificacion@infomercadolibre.com>",
			FromDomain:  "infomercadolibre.com",
			DKIMHeaders: []string{"v=1; d=oxsus-vadesecure.net; s=key1; b=xxx"},
		}
		result := CheckHeaders(pe)
		assert.False(t, result.DKIMAligned)
		assert.Contains(t, result.DKIMSigners, "oxsus-vadesecure.net")
	})

	t.Run("sin DKIM", func(t *testing.T) {
		pe := ParsedEmail{
			FromDomain:  "suspicious.com",
			DKIMHeaders: nil,
		}
		result := CheckHeaders(pe)
		assert.Empty(t, result.DKIMSigners)
		assert.False(t, result.DKIMAligned)
	})
}

func TestCheckHeaders_ReplyTo(t *testing.T) {
	t.Run("Reply-To en dominio diferente al remitente", func(t *testing.T) {
		pe := ParsedEmail{
			FromDomain: "mercadolibre.com",
			ReplyTo:    "soporte@attacker.com",
		}
		result := CheckHeaders(pe)
		assert.True(t, result.ReplyToDiffers)
	})

	t.Run("Reply-To en el mismo dominio", func(t *testing.T) {
		pe := ParsedEmail{
			FromDomain: "mercadolibre.com",
			ReplyTo:    "noreply@mercadolibre.com",
		}
		result := CheckHeaders(pe)
		assert.False(t, result.ReplyToDiffers)
	})

	t.Run("sin Reply-To", func(t *testing.T) {
		pe := ParsedEmail{
			FromDomain: "mercadolibre.com",
			ReplyTo:    "",
		}
		result := CheckHeaders(pe)
		assert.False(t, result.ReplyToDiffers)
	})
}

func TestRootDomain(t *testing.T) {
	cases := []struct{ domain, want string }{
		{"oxsus-vadesecure.net", "oxsus-vadesecure.net"}, // guión no separa subdominio
		{"mercadolibre.com", "mercadolibre.com"},
		{"mail.mercadolibre.com", "mercadolibre.com"},
		{"sub.sub.amazon.com", "amazon.com"},
		{"notificacion.infomercadolibre.com", "infomercadolibre.com"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, rootDomain(tc.domain), tc.domain)
	}
}
