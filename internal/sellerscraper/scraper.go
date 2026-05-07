package sellerscraper

// Result contiene el resultado del análisis de un perfil de vendedor
type Result struct {
	Platform   string      `json:"platform,omitempty"`
	SellerID   string      `json:"seller_id,omitempty"`
	Username   string      `json:"username,omitempty"`
	ProfileURL string      `json:"profile_url,omitempty"`
	Profile    ProfileData `json:"profile,omitempty"`
	RiskScore  int         `json:"risk_score,omitempty"`
	RiskLevel  string      `json:"risk_level,omitempty"`
	Flags      []string    `json:"flags,omitempty"`
}

type ProfileData struct {
	RegistrationDate  string  `json:"registration_date,omitempty"`
	AccountAgeDays    int     `json:"account_age_days,omitempty"`
	TotalTransactions int     `json:"total_transactions,omitempty"`
	CompletedSales    int     `json:"completed_sales,omitempty"`
	CanceledSales     int     `json:"canceled_sales,omitempty"`
	ComplaintRate     float64 `json:"complaint_rate,omitempty"`
	CancellationRate  float64 `json:"cancellation_rate,omitempty"`
	PositiveRating    float64 `json:"positive_rating,omitempty"`
	NegativeRating    float64 `json:"negative_rating,omitempty"`
	ReputationLevel   string  `json:"reputation_level,omitempty"`
	Country           string  `json:"country,omitempty"`
	IsNewAccount      bool    `json:"is_new_account,omitempty"`
}

// Analyze verifica el perfil de un vendedor dado su URL o username
//
// Uso:
//   guardian verify-seller https://www.mercadolibre.com.mx/perfil/VENDEDOR123
//   guardian verify-seller --platform mercadolibre VENDEDOR123
func Analyze(input, platform string) (Result, error) {
	// TODO: detectar plataforma automáticamente desde la URL si no se especifica
	// Patrones:
	//   mercadolibre.com.mx/perfil/  → mercadolibre
	//   amazon.com.mx/sp?seller=     → amazon
	//   aliexpress.com/store/        → aliexpress

	switch platform {
	case "mercadolibre", "":
		return analyzeMercadoLibre(input)
	case "amazon":
		return analyzeAmazon(input)
	case "aliexpress":
		return analyzeAliExpress(input)
	default:
		return Result{}, ErrUnsupportedPlatform(platform)
	}
}

func calculateRisk(r Result) (int, []string) {
	score := 0
	var flags []string

	p := r.Profile

	// Cuenta recién creada — señal fuerte en fraudes de comprador falso
	if p.AccountAgeDays < 30 {
		score += 40
		flags = append(flags, "cuenta creada hace menos de 30 días")
	} else if p.AccountAgeDays < 90 {
		score += 25
		flags = append(flags, "cuenta creada hace menos de 90 días")
	} else if p.AccountAgeDays < 180 {
		score += 10
		flags = append(flags, "cuenta creada hace menos de 6 meses")
	}

	// Sin historial de transacciones
	if p.IsNewAccount || p.TotalTransactions == 0 {
		score += 30
		flags = append(flags, "sin historial de transacciones")
	} else if p.TotalTransactions < 5 {
		score += 15
		flags = append(flags, "menos de 5 transacciones en total")
	}

	// Alta tasa de cancelaciones
	if p.CancellationRate > 0.15 {
		score += 20
		flags = append(flags, "tasa de cancelaciones alta: "+fmtPercent(p.CancellationRate))
	}

	// Alta tasa de reclamos
	if p.ComplaintRate > 0.10 {
		score += 20
		flags = append(flags, "tasa de reclamos alta: "+fmtPercent(p.ComplaintRate))
	}

	// Calificaciones negativas
	if p.NegativeRating > 0.15 {
		score += 20
		flags = append(flags, "calificaciones negativas: "+fmtPercent(p.NegativeRating))
	}

	if score > 100 {
		score = 100
	}
	return score, flags
}

func scoreToLevel(score int) string {
	switch {
	case score >= 75:
		return "CRITICO"
	case score >= 50:
		return "ALTO"
	case score >= 25:
		return "MEDIO"
	default:
		return "BAJO"
	}
}

func fmtPercent(f float64) string {
	pct := int(f * 100)
	return itoa(pct) + "%"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}
