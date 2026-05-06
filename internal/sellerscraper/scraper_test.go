package sellerscraper

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalculateRisk_CuentaNueva(t *testing.T) {
	t.Run("cuenta creada hace menos de 30 días — riesgo alto", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{AccountAgeDays: 15},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 40)
		assert.NotEmpty(t, flags)
		assert.Contains(t, flags[0], "30 días")
	})

	t.Run("cuenta creada hace menos de 90 días", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{AccountAgeDays: 60},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 25)
		assert.Contains(t, flags[0], "90 días")
	})

	t.Run("cuenta creada hace menos de 6 meses", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{AccountAgeDays: 120},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 10)
		assert.Contains(t, flags[0], "6 meses")
	})

	t.Run("cuenta con historial suficiente — no penaliza", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{
				AccountAgeDays:    365,
				TotalTransactions: 50,
			},
		}
		score, _ := calculateRisk(r)
		assert.Equal(t, 0, score)
	})
}

func TestCalculateRisk_SinTransacciones(t *testing.T) {
	t.Run("cuenta nueva sin ventas", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{
				AccountAgeDays: 365,
				IsNewAccount:   true,
			},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 30)
		assert.Contains(t, flags[0], "historial")
	})

	t.Run("menos de 5 transacciones", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{
				AccountAgeDays:    365,
				TotalTransactions: 3,
			},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 15)
		assert.NotEmpty(t, flags)
	})
}

func TestCalculateRisk_TasasCancelacionReclamos(t *testing.T) {
	t.Run("alta tasa de cancelaciones", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{
				AccountAgeDays:    365,
				TotalTransactions: 100,
				CancellationRate:  0.20,
			},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 20)
		assert.Contains(t, flags[0], "cancelaciones")
	})

	t.Run("alta tasa de reclamos", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{
				AccountAgeDays:    365,
				TotalTransactions: 100,
				ComplaintRate:     0.15,
			},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 20)
		assert.Contains(t, flags[0], "reclamos")
	})

	t.Run("calificaciones negativas altas", func(t *testing.T) {
		r := Result{
			Profile: ProfileData{
				AccountAgeDays:    365,
				TotalTransactions: 100,
				NegativeRating:    0.20,
			},
		}
		score, flags := calculateRisk(r)
		assert.GreaterOrEqual(t, score, 20)
		assert.Contains(t, flags[0], "negativas")
	})
}

func TestCalculateRisk_Cap100(t *testing.T) {
	r := Result{
		Profile: ProfileData{
			AccountAgeDays:    5,
			IsNewAccount:      true,
			CancellationRate:  0.50,
			ComplaintRate:     0.50,
			NegativeRating:    0.50,
			TotalTransactions: 1,
		},
	}
	score, _ := calculateRisk(r)
	assert.Equal(t, 100, score)
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

func TestErrUnsupportedPlatform(t *testing.T) {
	err := ErrUnsupportedPlatform("tiktok")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tiktok")
	assert.Contains(t, err.Error(), "mercadolibre")
}

func TestFmtPercent(t *testing.T) {
	assert.Equal(t, "20%", fmtPercent(0.20))
	assert.Equal(t, "5%", fmtPercent(0.05))
	assert.Equal(t, "0%", fmtPercent(0.0))
	assert.Equal(t, "100%", fmtPercent(1.0))
}
