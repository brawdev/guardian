package emailanalyzer

// officialSenderDomains mapea marca → dominios legítimos de envío
// Cobertura: marketplaces LATAM/MX de mayor volumen de fraude reportado
var officialSenderDomains = map[string][]string{
	// --- Marketplaces globales con alta actividad en LATAM ---
	"mercadolibre": {
		"mercadolibre.com", "mercadopago.com",
		"mercadolibre.com.mx", "mercadolibre.com.ar",
		"mercadolibre.com.co", "mercadolibre.com.cl",
		"mercadolibre.com.pe", "mercadolivre.com.br",
		"mercadolibre.com.ve",
	},
	"amazon": {
		"amazon.com", "amazon.com.mx", "amazon.com.br",
		"amazon.co.uk", "amazon.de", "amazon.fr",
		"amazon-email.com", "ses.amazonaws.com",
		"marketplace.amazon.com",
	},
	"aliexpress": {
		"aliexpress.com", "alibaba.com",
		"aliexpress-notifications.com",
	},
	"shein": {
		"shein.com", "shein.com.mx",
	},
	"paypal": {
		"paypal.com", "paypal-communication.com",
		"paypal.com.mx",
	},
	"ebay": {
		"ebay.com", "ebay.com.mx",
	},

	// --- Tiendas departamentales México ---
	"walmart":  {"walmart.com", "walmart.com.mx"},
	"liverpool": {"liverpool.com.mx"},
	"coppel":   {"coppel.com"},
	"elektra":  {"elektra.com.mx"},

	// --- Turismo (sector con mayor monto defraudado) ---
	"booking":   {"booking.com"},
	"airbnb":    {"airbnb.com", "airbnb.com.mx"},
	"expedia":   {"expedia.com", "expedia.com.mx"},
	"aeromexico": {"aeromexico.com"},
	"volaris":   {"volaris.com"},
}

// urgencyKeywords frases de urgencia en español — marketplace/e-commerce
var urgencyKeywords = []string{
	"12 horas", "24 horas", "48 horas",
	"inmediatamente", "urgente", "de inmediato",
	"será bloqueado", "sera bloqueado",
	"será suspendido", "sera suspendido",
	"marcado como fraudulento", "marcado fraudulento",
	"comunidad como fraudulento", "comunidad como fraudulentas",
	"perderás tu dinero", "perderas tu dinero",
	"procede con el envío", "procede con el envio",
	"reservar el stock",
	"calificación de tu comprador", "calificacion de tu comprador",
	"validar tu venta",
	"pausar la publicación", "pausar la publicacion",
	"pago pausado", "pago ha sido pausado",
	"mantenimiento rutinario",
	"proceso de desembolso", "desembolso de fondos",
	"no puede ser cancelada", "esta operacion no puede",
	"baja reputación", "baja reputacion",
	"puntos necesarios para liberar",
	// Turismo
	"confirmar tu reserva", "confirmar reservacion",
	"tu vuelo fue cancelado", "reprogramar tu vuelo",
	"reembolso pendiente", "gestionar tu reembolso",
	"tu reserva expira", "oferta por tiempo limitado",
}

// urgencyKeywordsEN frases de urgencia en inglés — marketplace/e-commerce
var urgencyKeywordsEN = []string{
	"24 hours", "12 hours", "48 hours",
	"immediately", "urgent", "right away",
	"will be suspended", "will be blocked", "will be locked",
	"marked as fraudulent", "marked as fraud",
	"lose your money", "lose your funds",
	"proceed with shipment", "proceed with shipping",
	"reserve the stock",
	"buyer rating", "buyer feedback",
	"validate your sale", "verify your sale",
	"pause your listing",
	"payment on hold", "payment has been paused", "payment is paused",
	"routine maintenance",
	"disbursement process", "release of funds", "funds release",
	"cannot be cancelled", "cannot be canceled",
	"low reputation", "poor reputation",
	"points needed to release",
	"action required", "verify immediately", "confirm immediately",
	"your account will be", "account suspended", "account blocked",
	// Turismo en inglés
	"confirm your booking", "booking expires",
	"your flight was cancelled", "reschedule your flight",
	"pending refund", "claim your refund",
	"limited time offer", "offer expires",
}

// creditCardKeywords palabras clave que indican solicitud de datos de tarjeta
// Ninguna empresa legítima pide estos datos por email
var creditCardKeywords = []string{
	"cvv", "cvc", "número de tarjeta", "numero de tarjeta",
	"fecha de vencimiento", "fecha venc", "fecha exp",
	"datos de tdc", "tarjeta de crédito", "tarjeta de credito",
	"número de tdc", "numero de tdc",
	// Inglés
	"card number", "credit card number", "expiry date",
	"expiration date", "security code", "card details",
}

// identityKeywords solicitudes de documentos de identidad por email
var identityKeywords = []string{
	// México
	"número de ine", "numero de ine", "datos de ine",
	"clave de elector", "curp", "rfc",
	"copia de ine", "foto de ine",
	// Genérico LATAM
	"cédula de identidad", "cedula de identidad",
	"dni", "pasaporte",
	// Inglés
	"passport number", "national id", "social security",
	"government id", "photo id",
}

// tldToPhonePrefix mapea TLD de país al código telefónico esperado
var tldToPhonePrefix = map[string][]string{
	".com.mx": {"+52"},
	".mx":     {"+52"},
	".com.br": {"+55"},
	".br":     {"+55"},
	".com.co": {"+57"},
	".co":     {"+57"},
	".com.ar": {"+54"},
	".ar":     {"+54"},
	".com.cl": {"+56"},
	".cl":     {"+56"},
	".com.pe": {"+51"},
	".pe":     {"+51"},
	".com.ve": {"+58"},
	".ve":     {"+58"},
	".com.ec": {"+593"},
	".ec":     {"+593"},
	".es":     {"+34"},
	".com.es": {"+34"},
	".com.au": {"+61"},
	".au":     {"+61"},
	".co.uk":  {"+44"},
	".uk":     {"+44"},
	".de":     {"+49"},
	".fr":     {"+33"},
	".ca":     {"+1"},
}

// brandToPhonePrefix para marcas .com con mercado principal definido
var brandToPhonePrefix = map[string][]string{
	"mercadolibre": {"+52", "+54", "+55", "+56", "+57", "+58", "+51", "+593", "+598"},
	"mercadopago":  {"+52", "+54", "+55", "+56", "+57", "+58", "+51", "+593", "+598"},
	"liverpool":    {"+52"},
	"elektra":      {"+52"},
	"coppel":       {"+52"},
	"walmart":      {"+1", "+52"},
	"aeromexico":   {"+52"},
	"volaris":      {"+52"},
}

// personalTrackers dominios de rastreadores personales de email
// (ilegítimos en comunicaciones oficiales de empresas)
var personalTrackers = []string{
	"mailtrack.io",
	"mailsuite",
	"list-prefs.com",
	"getmailspring.com",
	"bananatag.com",
	"yesware.com",
	"streak.com",
}
