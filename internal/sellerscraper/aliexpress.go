package sellerscraper

import "errors"

// analyzeAliExpress verifica un perfil de tienda en AliExpress
//
// TODO: implementar
//
// OPCIONES:
//
//   OPCIÓN A — AliExpress Affiliate API:
//     https://developers.aliexpress.com/
//     Requiere registro como afiliado. Permite consultar datos de tiendas y productos.
//
//   OPCIÓN B — Scraping de página pública de tienda:
//     URL: https://www.aliexpress.com/store/{STORE_ID}
//     Datos visibles: nombre, calificación, seguidores, tiempo activo, país de origen.
//     Nota: AliExpress sirve contenido dinámico (React/JS) — requiere headless browser
//     o inspeccionar las llamadas XHR que hace la página.
//
// CAMPOS OBJETIVO:
//   - Nombre de la tienda
//   - País de origen del vendedor (señal importante — China vs. país del comprador)
//   - Años activo en la plataforma
//   - Puntuación de la tienda (positive feedback %)
//   - Número de seguidores / transacciones
func analyzeAliExpress(input string) (Result, error) {
	// TODO: implementar con la opción elegida

	return Result{}, errors.New("TODO: AliExpress seller scraper no implementado — ver opciones en aliexpress.go")
}
