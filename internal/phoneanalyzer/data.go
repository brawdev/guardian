package phoneanalyzer

var countryPrefixes = map[string]string{
	"+52":  "México",
	"+1":   "EE.UU./Canadá",
	"+55":  "Brasil",
	"+54":  "Argentina",
	"+57":  "Colombia",
	"+56":  "Chile",
	"+51":  "Perú",
	"+58":  "Venezuela",
	"+593": "Ecuador",
	"+595": "Paraguay",
	"+598": "Uruguay",
	"+502": "Guatemala",
	"+503": "El Salvador",
	"+504": "Honduras",
	"+505": "Nicaragua",
	"+506": "Costa Rica",
	"+507": "Panamá",
	"+34":  "España",
	"+44":  "Reino Unido",
	"+49":  "Alemania",
	"+33":  "Francia",
	"+39":  "Italia",
	"+86":  "China",
	"+91":  "India",
	"+7":   "Rusia",
	"+234": "Nigeria",
	"+27":  "Sudáfrica",
}

type voipRange struct {
	prefix   string
	provider string
}

var voipRanges = []voipRange{
	// Twilio — rangos comunes
	{"+1800", "Twilio/toll-free"},
	{"+1888", "Twilio/toll-free"},
	{"+1877", "Twilio/toll-free"},
	{"+1866", "Twilio/toll-free"},
	// Google Voice (EE.UU.)
	{"+1760", "Google Voice (posible)"},
	{"+1442", "Google Voice (posible)"},
	// TextNow / TextFree — prefijos de spam conocidos
	{"+1855", "VoIP/toll-free"},
	{"+1844", "VoIP/toll-free"},
	{"+1833", "VoIP/toll-free"},
	// Números 900 (servicios de tarificación especial MX)
	{"+52900", "México 900 (tarificación especial)"},
}
