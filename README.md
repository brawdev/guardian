# Guardian

Herramienta para detectar fraude, phishing y estafas en e-commerce. Disponible como CLI y como API REST. Analiza URLs sospechosas y correos electrónicos antes de que hagas clic, respondas o envíes un producto.

---

## El problema que resuelve

El fraude por e-commerce funciona así: recibes un correo que parece venir de MercadoLibre, Amazon o PayPal. El diseño se ve igual. La dirección del remitente suena oficial. Te piden actuar rápido o perderás el pago.

**My Guardian detecta esas señales antes de que sea tarde.**

### Cobertura

La herramienta está optimizada para las plataformas con mayor volumen de fraude reportado en México y LATAM, divididas en cuatro categorías:

| Categoría | Marcas cubiertas |
|-----------|-----------------|
| **Marketplaces globales** | Amazon, MercadoLibre / MercadoPago, AliExpress, Shein, eBay, PayPal |
| **Tiendas departamentales MX** | Walmart, Liverpool, Coppel, Elektra |
| **Turismo** | Booking.com, Airbnb, Expedia, Aeroméxico, Volaris |
| **Dominios de phishing** | Detección genérica por patrones (typosquatting, dominio nuevo, SSL inválido) |

> La detección de patrones de phishing (dominio falso, DKIM, urgencia, cuenta bancaria, CVV) funciona para cualquier remitente — no solo las marcas listadas. La tabla anterior indica dónde la detección es más precisa porque se conocen los dominios oficiales de envío.

---

## Instalación

```bash
git clone https://github.com/brawdev/guardian
cd guardian
go build -o guardian .
```

Opcional — mover el binario para usarlo desde cualquier carpeta:

```bash
mv guardian /usr/local/bin/
```

---

## API REST

Guardian también puede correr como servidor HTTP para integrarse con bots, apps o cualquier cliente.

### Levantar el servidor

```bash
guardian serve              # puerto 8080 por defecto
guardian serve --port 9090
```

### Endpoints

#### `GET /health`

Verifica que el servidor esté corriendo.

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

---

#### `POST /api/v1/analyze/url`

Analiza una URL en busca de phishing o fraude.

```bash
curl -X POST http://localhost:8080/api/v1/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://amaz0n-ofertas.com"}'
```

**Body:**

| Campo | Tipo | Requerido |
|-------|------|-----------|
| `url` | string | Sí |

**Qué detecta:**

| Señal | Descripción |
|-------|-------------|
| Typosquatting | Dominios que imitan marcas (`amaz0n`, `infomercadolibre`, `paypa1`) |
| Punycode/IDN | Dominios con caracteres Unicode que se ven idénticos a marcas reales (`xn--mercadolbre-q1b.com`) |
| URL cortos | Expande `bit.ly`, `tinyurl`, `t.co`, etc. antes de analizar el destino real |
| Dominio nuevo | Creado hace menos de 90 días |
| SSL inválido | Certificado autofirmado o vencido |
| Redirecciones | Cadenas que cambian de dominio |
| Google Safe Browsing | Base de datos de sitios maliciosos |
| VirusTotal | Verificación contra +90 motores antivirus |

---

#### `POST /api/v1/analyze/seller`

Verifica el perfil de un vendedor en un marketplace.

```bash
curl -X POST http://localhost:8080/api/v1/analyze/seller \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.mercadolibre.com.mx/perfil/VENDEDOR123", "platform": "mercadolibre"}'
```

**Body:**

| Campo | Tipo | Requerido | Valores |
|-------|------|-----------|---------|
| `url` | string | Sí | URL del perfil |
| `platform` | string | No | `mercadolibre`, `amazon`, `aliexpress` |

---

#### `POST /api/v1/analyze/email`

Analiza un correo sospechoso. Acepta dos formatos según lo que tengas disponible.

**Opción A — Texto plano (JSON)**

```bash
curl -X POST http://localhost:8080/api/v1/analyze/email \
  -H "Content-Type: application/json" \
  -d '{"content": "From: Mercado Libre <notificacion@infomercadolibre.com>\nSubject: ..."}'
```

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `content` | string | Contenido raw del correo |

**Cómo obtener el contenido desde Gmail:**
1. Abre el correo en Gmail
2. Menú de tres puntos → **"Mostrar original"**
3. **Ctrl+A** → **Cmd+C** para copiar todo
4. Pega el texto como valor del campo `content`

---

**Opción B — Archivo `.eml` (multipart)**

```bash
curl -X POST http://localhost:8080/api/v1/analyze/email \
  -F "file=@correo.eml"
```

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `file` | archivo | Archivo `.eml` descargado desde Gmail |

**Cómo obtener el `.eml` desde Gmail:**
1. Abre el correo en Gmail
2. Menú de tres puntos → **"Descargar original"**
3. Se descarga el archivo `.eml` con headers completos

> Ambas opciones incluyen headers técnicos completos (DKIM, SPF, Authentication-Results), activando todos los checks de autenticidad del remitente.

---

#### `POST /api/v1/analyze/phone`

Analiza un número de teléfono en busca de señales de fraude.

```bash
curl -X POST http://localhost:8080/api/v1/analyze/phone \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1800 555 1234", "country_context": "MX"}'
```

**Body:**

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `phone` | string | Sí | Número con o sin código de país |
| `country_context` | string | No | País esperado: `MX`, `US`, `BR`, `AR`, `CO`, `CL`, `PE`, `ES` |

**Qué detecta:**

| Señal | Descripción |
|-------|-------------|
| Formato inválido | Número no reconocido o con menos de 7 dígitos |
| Número VoIP | Twilio, Google Voice, toll-free — frecuentes en fraude telefónico |
| País inconsistente | Número de EE.UU. en contexto de México, por ejemplo |

---

## Comandos CLI

### `analyze` — Analiza una URL

Antes de abrir un enlace sospechoso, analízalo.

```bash
guardian analyze <url>
```

**Ejemplos:**

```bash
guardian analyze https://infomercadolibre.com
guardian analyze amaz0n-ofertas.com
guardian analyze https://mercadolibre-descuentos.mx --json
```

**Qué detecta:**

| Señal | Descripción |
|-------|-------------|
| Typosquatting | Dominios que imitan marcas conocidas (`amaz0n`, `infomercadolibre`, `paypa1`) |
| Dominio nuevo | Dominios creados hace menos de 90 días — típico en sitios de fraude |
| SSL inválido | Certificado autofirmado o vencido |
| Redirecciones | Cadenas de redirección que cambian de dominio |
| Google Safe Browsing | Base de datos de sitios maliciosos de Google |
| VirusTotal | Verificación contra más de 90 motores antivirus y reputación web |

**Ejemplo de salida:**

```
  ANÁLISIS DE URL
  ──────────────────────────────────────────────────
  URL:      https://mercadolibre-verificacion.xyz
  Dominio:  mercadolibre-verificacion.xyz

  Riesgo:   CRITICO  (90/100)

  CHECKS
  ⚠  Typosquatting    contiene la marca 'mercadolibre' en el dominio
  ⚠  WHOIS            dominio creado 2025-03-01 (12 días)
  ✓  SSL/TLS          válido — emisor: Let's Encrypt
  ✓  Redirecciones    sin redirecciones
  ✓  Safe Browsing    limpio
  ✗  VirusTotal       3/89 engines — Kaspersky, ESET, Avast
```

---

### `analyze-email` — Analiza un correo sospechoso

Detecta patrones de fraude principalmente en **español** (validado contra correos reales de fraude en México). La cobertura es más precisa para las marcas listadas en la tabla anterior.

Tres formas de usarlo según lo que tengas a la mano:

---

#### Opción A — Pegar el texto directamente (más fácil)

```bash
guardian analyze-email --paste
```

La terminal queda esperando. Pegas el texto con **Cmd+V** y presionas **Ctrl+D** para analizar.

**Flujo recomendado desde Gmail:**
1. Abre el correo sospechoso
2. Menú de tres puntos → **"Ver original"**
3. **Ctrl+A** para seleccionar todo → **Cmd+C** para copiar
4. En la terminal: `guardian analyze-email --paste` → **Cmd+V** → **Ctrl+D**

> Si solo copias el texto visible (sin "Ver original"), igual funciona — solo perderás el análisis de cabeceras técnicas (DKIM, dominio del remitente).

---

#### Opción B — Desde el clipboard (Mac)

```bash
pbpaste | guardian analyze-email -
```

---

#### Opción C — Desde un archivo `.eml`

Si exportaste el correo como archivo:

```bash
guardian analyze-email correo.eml
guardian analyze-email ~/Downloads/sospechoso.eml --json
```

---

**Qué detecta en el correo:**

| Señal | Por qué importa |
|-------|-----------------|
| Dominio del remitente falso | `notificacion@infomercadolibre.com` no es MercadoLibre — se compara contra dominios oficiales conocidos |
| Display name spoofing | `"Mercado Libre" <estafa@gmail.com>` — el nombre visible suplanta la marca pero el dominio es diferente |
| SPF ausente o permisivo | El dominio no tiene política SPF o permite cualquier servidor enviar en su nombre |
| DMARC ausente o en `none` | Sin política de rechazo activa — cualquiera puede falsificar el remitente |
| DKIM no alineado | El correo fue firmado por un dominio diferente al remitente — señal técnica de suplantación |
| Links ocultos | Texto visible `mercadolibre.com` que en realidad apunta a `phishing.com` |
| Soporte vía WhatsApp | Ningún marketplace real usa `wa.me` para soporte oficial |
| Solicitud de transferencia bancaria | Piden depositar a una cuenta externa en lugar de usar la plataforma |
| Frases de urgencia o amenaza | "12 horas", "será bloqueado", "pago pausado", "desembolso de fondos" — patrones extraídos de correos reales |
| Solicitud de datos de tarjeta | CVV, número de tarjeta, fecha de vencimiento — ninguna empresa legítima pide esto por email |
| Solicitud de documentos de identidad | INE, CURP, RFC, DNI, pasaporte — señal de robo de identidad |
| Rastreadores personales | Mailtrack o Mailsuite en un correo "oficial" — lo envía una persona, no una empresa |
| Teléfono de país inconsistente | `+86` (China) en un correo de Shein México (`@shein.com.mx`) — detectado por TLD |
| Links sospechosos en el cuerpo | Cada link externo se analiza con el mismo motor que `analyze` |

**Ejemplo de salida:**

```
  ANÁLISIS DE EMAIL
  ──────────────────────────────────────────────────
  De:      Mercado Libre <notificacion@infomercadolibre.com>
  Asunto:  ¡Vendiste! Macbook Pro Core I7 Retina 16 Pulgadas

  Riesgo:  CRITICO  (100/100)

  CHECKS DE CABECERAS
  ✗  From domain      'infomercadolibre.com' suplanta a 'mercadolibre'
  ⚠  DKIM             firmado por 'oxsus-vadesecure.net' — no alineado con from-domain
  ✓  Reply-To         consistente

  CHECKS DE CONTENIDO
  ✗  Soporte          vía WhatsApp: https://wa.me/+5491176499251
  ✗  Cuenta bancaria  0087-6676-011032629274
  ✗  Urgencia/amenaza 7 frases detectadas
  ✓  Tarjeta crédito  sin solicitudes de datos de tarjeta
  ✗  Docs identidad   1 señales: curp
  ⚠  Email tracker    mailtrack.io, mailsuite
  ✓  Teléfonos        sin inconsistencias de país

  LINKS EN EL CUERPO
  ✗  https://mercadolibre-verificacion.xyz  CRITICO  (90/100) — impersonación de marca

  SEÑALES DE ALERTA
  ✗ dominio del remitente 'infomercadolibre.com' suplanta a 'mercadolibre'
  ✗ DKIM firmado por 'oxsus-vadesecure.net' ≠ 'infomercadolibre.com'
  ✗ soporte vía WhatsApp: https://wa.me/+5491176499251
  ✗ solicita transferencia a cuenta bancaria: 0087-6676-011032629274
  ✗ múltiples frases de urgencia/amenaza (7 detectadas)
  ✗ link CRITICO en el cuerpo: https://mercadolibre-verificacion.xyz
```

---

## Niveles de riesgo

| Nivel | Puntuación | Qué hacer |
|-------|-----------|-----------|
| BAJO | 0 – 24 | Sin señales de alerta detectadas |
| MEDIO | 25 – 49 | Revisar con cuidado antes de actuar |
| ALTO | 50 – 74 | Alta probabilidad de fraude |
| CRITICO | 75 – 100 | No interactuar — reportar y eliminar |

---

## Output en JSON

Cualquier comando acepta `--json` para integrar la salida con otras herramientas:

```bash
guardian analyze https://sitio-sospechoso.com --json
guardian analyze-email correo.eml --json
guardian analyze-email --paste --json
```

---

## Variables de entorno

Crea un archivo `.env` en la raíz del proyecto:

```env
GOOGLE_SAFE_BROWSING_KEY=tu_api_key_aqui
VIRUSTOTAL_KEY=tu_api_key_aqui
```

| Key | Dónde obtenerla | Sin ella... |
|-----|-----------------|-------------|
| `GOOGLE_SAFE_BROWSING_KEY` | [Google Safe Browsing](https://developers.google.com/safe-browsing/v4/get-started) — gratis | Se omite ese check |
| `VIRUSTOTAL_KEY` | [virustotal.com](https://www.virustotal.com) — gratis, 4 req/min | Se omite ese check |

Los demás análisis (typosquatting, WHOIS, SSL, redirecciones, cabeceras de email) funcionan sin ninguna key.
