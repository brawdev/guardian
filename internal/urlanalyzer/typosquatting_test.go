package urlanalyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckTyposquatting_BrandContainment(t *testing.T) {
	cases := []struct {
		hostname string
		brand    string
	}{
		{"infomercadolibre.com", "mercadolibre"},
		{"pagos-mercadolibre.com.mx", "mercadolibre"},
		{"amazon-ofertas.com.mx", "amazon"},
		{"soporte-paypal.com", "paypal"},
		{"booking-ofertas-mexico.com", "booking"},
		{"aliexpress-descuentos.com", "aliexpress"},
	}

	for _, tc := range cases {
		t.Run(tc.hostname, func(t *testing.T) {
			result := CheckTyposquatting(tc.hostname)
			assert.True(t, result.IsTyposquat, "debería detectar typosquat")
			assert.Equal(t, "contains", result.MatchType)
			assert.Equal(t, tc.brand, result.ClosestBrand)
		})
	}
}

func TestCheckTyposquatting_Homoglyphs(t *testing.T) {
	cases := []struct {
		hostname string
		brand    string
	}{
		{"amaz0n.com", "amazon"},
		{"paypa1.com", "paypal"},
	}

	for _, tc := range cases {
		t.Run(tc.hostname, func(t *testing.T) {
			result := CheckTyposquatting(tc.hostname)
			assert.True(t, result.IsTyposquat)
			assert.Equal(t, "homoglyph", result.MatchType)
			assert.Equal(t, tc.brand, result.ClosestBrand)
		})
	}
}

func TestCheckTyposquatting_Levenshtein(t *testing.T) {
	cases := []struct {
		hostname string
		brand    string
	}{
		{"amazom.com", "amazon"},
		{"mercadolibree.com", "mercadolibre"},
	}

	for _, tc := range cases {
		t.Run(tc.hostname, func(t *testing.T) {
			result := CheckTyposquatting(tc.hostname)
			assert.True(t, result.IsTyposquat)
			assert.Equal(t, tc.brand, result.ClosestBrand)
		})
	}
}

func TestCheckTyposquatting_LegitimoDomains(t *testing.T) {
	legit := []string{
		"amazon.com",
		"mercadolibre.com",
		"google.com",
		"github.com",
	}

	for _, hostname := range legit {
		t.Run(hostname, func(t *testing.T) {
			result := CheckTyposquatting(hostname)
			assert.False(t, result.IsTyposquat, "dominio legítimo no debería ser flaggeado")
		})
	}
}

func TestNormalizeHomoglyphs(t *testing.T) {
	assert.Equal(t, "amazon", normalizeHomoglyphs("amaz0n"))
	assert.Equal(t, "paypal", normalizeHomoglyphs("paypa1"))
	assert.Equal(t, "ebay", normalizeHomoglyphs("3bay"))
	assert.Equal(t, "amazon", normalizeHomoglyphs("amazon")) // sin cambios
}

func TestStripTLD(t *testing.T) {
	cases := []struct{ hostname, want string }{
		{"amazon.com", "amazon"},
		{"amazon.com.mx", "amazon"},
		{"mercadolibre.com.ar", "mercadolibre"},
		{"sub.domain.co.uk", "sub.domain"},
		{"google.com", "google"},
	}

	for _, tc := range cases {
		t.Run(tc.hostname, func(t *testing.T) {
			assert.Equal(t, tc.want, stripTLD(tc.hostname))
		})
	}
}
