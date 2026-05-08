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

	// Paquetería y couriers — frecuentemente suplantados en fraude de entregas
	"estafeta", "fedex", "dhl", "ups", "correosdemexico", "redpack",
	"paquetexpress", "sendex", "afimex",

	// Bancos y fintech México — alto riesgo de phishing financiero
	"bbva", "banamex", "citibanamex", "santander", "hsbc", "banorte",
	"inbursa", "scotiabank", "azteca", "nu", "nubank", "clip", "conekta",
	"oxxopay", "spin",

	// Gobierno México — suplantación para fraudes de trámites
	"sat", "imss", "issste", "infonavit", "condusef", "profeco",
}

// suspiciousTLDs TLDs frecuentemente usados en sitios de phishing y fraude
var suspiciousTLDs = []string{
	".sbs", ".xyz", ".top", ".click", ".work", ".gq", ".tk", ".ml",
	".ga", ".cf", ".icu", ".buzz", ".cyou", ".cfd", ".monster",
	".hair", ".beauty", ".boats", ".homes", ".lol",
}
