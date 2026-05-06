package urlanalyzer

// knownBrands marcas cubiertas para detección de typosquatting
// Basado en plataformas con mayor volumen de fraude reportado en LATAM/MX
var knownBrands = []string{
	// Marketplaces globales con alta actividad en LATAM
	"amazon", "mercadolibre", "mercadopago", "aliexpress", "alibaba",
	"shein", "temu", "ebay", "paypal",

	// Tiendas departamentales México
	"walmart", "liverpool", "coppel", "elektra", "sears", "sanborns",
	"palacio", "claroshop",

	// Turismo (mayor monto defraudado por incidente)
	"booking", "airbnb", "expedia", "aeromexico", "volaris",
	"viva", "interjet",
}
