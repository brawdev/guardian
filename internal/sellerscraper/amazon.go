package sellerscraper

import "errors"

// analyzeAmazon verifica un perfil de vendedor en Amazon
//
// TODO: implementar
//
// OPCIONES (de más a menos viable):
//
//   OPCIÓN A — Amazon Product Advertising API (requiere cuenta de afiliados):
//     https://webservices.amazon.com/paapi5/documentation/
//     Permite consultar información de vendedores asociados a productos.
//     Requiere: asociarse al programa de afiliados de Amazon.
//
//   OPCIÓN B — Scraping de la página pública del vendedor:
//     URL: https://www.amazon.com.mx/sp?seller={SELLER_ID}
//     Datos visibles: nombre, rating, número de reseñas, tiempo en Amazon.
//     Riesgo: Amazon detecta y bloquea scrapers con frecuencia.
//     Mitigación: respetar rate limits, usar headers realistas, no usar en producción masiva.
//
//   OPCIÓN C — API de terceros (ScrapeOps, Rainforest API):
//     Servicios pagos que ofrecen datos de Amazon vía API.
//     Costo: ~$30-50 USD/mes para uso personal básico.
//
// CAMPOS OBJETIVO:
//   - Nombre del vendedor
//   - Fecha de inicio en Amazon (no siempre visible)
//   - Porcentaje de calificaciones positivas (últimos 12 meses)
//   - Número total de reseñas
//   - Tiempo de respuesta
func analyzeAmazon(input string) (Result, error) {
	// TODO: implementar con la opción elegida

	return Result{}, errors.New("TODO: Amazon seller scraper no implementado — ver opciones en amazon.go")
}
