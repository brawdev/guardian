package sellerscraper

import "errors"

// analyzeMercadoLibre verifica un perfil de vendedor/comprador en MercadoLibre
//
// TODO: implementar con la API oficial de MercadoLibre v2
//
// AUTENTICACIÓN REQUERIDA:
//   La API pública de MercadoLibre requiere OAuth 2.0.
//   Pasos:
//     1. Crear app en https://developers.mercadolibre.com
//     2. Obtener CLIENT_ID y CLIENT_SECRET
//     3. Implementar flujo de autorización o usar app_token para consultas públicas
//     4. Agregar MERCADOLIBRE_APP_ID y MERCADOLIBRE_SECRET al .env
//
// ENDPOINTS A USAR:
//   Buscar por nickname:   GET /users/search?nickname={nickname}&site_id=MLM
//   Obtener por ID:        GET /users/{user_id}
//   Reputación:            GET /users/{user_id} → campo seller_reputation
//
// CAMPOS RELEVANTES DE LA RESPUESTA:
//   {
//     "id": 123456,
//     "nickname": "VENDEDOR123",
//     "registration_date": "2024-01-15T10:00:00.000-04:00",
//     "seller_reputation": {
//       "level_id": "5_green",
//       "transactions": {
//         "completed": 45,
//         "canceled": 2,
//         "total": 47,
//         "ratings": { "positive": 0.93, "negative": 0.02, "neutral": 0.05 }
//       },
//       "metrics": {
//         "cancellations": { "rate": 0.02 },
//         "claims":        { "rate": 0.01 }
//       }
//     },
//     "address": { "country_id": "MX", "state": "Jalisco", "city": "Guadalajara" }
//   }
//
// SITE IDs POR PAÍS:
//   MLM = México | MLA = Argentina | MLB = Brasil | MLC = Chile | MCO = Colombia
func analyzeMercadoLibre(input string) (Result, error) {
	// TODO: extraer nickname o ID desde URL o string directo
	// TODO: llamar GET /users/search?nickname={input}&site_id=MLM
	// TODO: si es ID numérico, llamar GET /users/{id} directamente
	// TODO: mapear respuesta a ProfileData
	// TODO: llamar calculateRisk y scoreToLevel

	return Result{}, errors.New("TODO: MercadoLibre seller scraper no implementado — requiere OAuth app en developers.mercadolibre.com")
}
