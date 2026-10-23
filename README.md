# sign_engine

Motor de **firma digital de PDFs escrito en [Bend](https://bend-lang.com/)**: un
conjunto de librerías (bytes, SHA-256, enteros grandes, RSA, ASN.1/DER, X.509,
CMS, DEFLATE, PDF) más una aplicación que firma documentos y un servicio HTTP
que expone la API a la web.

Las firmas producidas son **PAdES B-B** (`/SubFilter /ETSI.CAdES.detached`,
RSA PKCS#1 v1.5 + SHA-256) y validan en pyHanko y en poppler (`pdfsig`):

```
[Firma12] intact=True valid=True trusted=True coverage=ENTIRE_FILE modification=NONE
    /Reason = Firma de prueba RSA-2048
pdfsig: 1 firma(s) válida(s)
```

## Arquitectura

```
                 ┌────────────────────────── Bend ──────────────────────────┐
 HTTP / JSON     │                                                            │
 ───────────▶ service/server.py ──▶ build/sign (sign.bend compilado a C)     │
 (Python, sólo   │   prepara input.pdf,        │                              │
  transporte)    │   key.pem, cert.pem,        ▼                              │
                 │   params.txt           lib/signer.bend  (orquestación)     │
                 │                    ┌────────┼──────────────┬──────────┐    │
                 │                    ▼        ▼              ▼          ▼    │
                 │               lib/pdf   lib/cms       lib/x509   lib/rsa   │
                 │                    │        │              │          │    │
                 │               lib/inflate  lib/sha256   lib/asn1  lib/bigint│
                 │                    └────────┴──────┬───────┴──────────┘    │
                 │                                lib/bytes                   │
                 └────────────────────────────────────────────────────────────┘
```

Bend 0.2 no tiene sockets ni argumentos de línea de comandos en los binarios
compilados, por eso el servicio web es una capa delgada en Python (biblioteca
estándar) que sólo valida la entrada y ejecuta el binario. **Todo el
procesamiento criptográfico y del PDF ocurre en Bend.**

## Librerías (`lib/`)

| Librería | Contenido |
|---|---|
| `bytes.bend` | Listas de bytes: concatenación, cortes, búsqueda (`find`/`rfind`), hex, base64, decimal, normalización de E/S (`Bytes/from_io`). |
| `sha256.bend` | SHA-256 (FIPS 180-4). Palabras de 32 bits como pares de 16 bits; rondas "aplanadas" para reducir interacciones en HVM. |
| `bigint.bend` | Enteros de precisión arbitraria en limbs de 12 bits, multiplicación de Montgomery (CIOS) y exponenciación modular con ventana fija de 4 bits. |
| `rsa.bend` | RSA PKCS#1 v1.5 con SHA-256, operación privada con CRT y verificación de la firma antes de entregarla (contramedida ante fallos). |
| `asn1.bend` | Codificador/decodificador DER y lector PEM. |
| `x509.bend` | Llaves privadas RSA (PKCS#1 y PKCS#8 sin cifrar) y certificados X.509 (emisor, serie, CN, llave pública). |
| `cms.bend` | CMS `SignedData` detached con atributos firmados CAdES (contentType, messageDigest, signingCertificateV2). API en dos pasos, apta para firmar fuera de Bend (HSM). |
| `inflate.bend` | Descompresión DEFLATE/zlib y predictores PNG (necesarios para xref streams y object streams). |
| `pdf.bend` | Parser/serializador de objetos PDF, tablas xref clásicas, xref streams, archivos híbridos, object streams, cadenas `/Prev`, y escritura de la actualización incremental con `/ByteRange`. |
| `signer.bend` | Orquestación: `Signer/sign_pdf(pdf, llave, certificados, parámetros)`. |

Cómo se firma (resumen de `lib/signer.bend`):

1. `Pdf/analyze` localiza `startxref`, carga todas las secciones xref, el catálogo y la primera página.
2. `Pdf/prepare` agrega en una actualización incremental el diccionario `/Sig`, el widget del campo de firma, el catálogo con `/AcroForm` y la página con `/Annots`, reservando `/Contents` y calculando el `/ByteRange` definitivo.
3. Se calcula SHA-256 de los rangos cubiertos, se arman los atributos firmados y se firma con RSA (CRT).
4. `Cms/assemble` arma el `SignedData` y `Pdf/finish` lo inserta en hexadecimal en `/Contents`.

## Requisitos

- Rust/cargo para instalar Bend y HVM: `cargo install hvm bend-lang` (probado con **bend-lang 0.2.38** y **hvm 2.0.22**)
- gcc
- Python ≥ 3.9 para el servicio (sólo biblioteca estándar)
- Para las pruebas: `openssl`, `pip install pyhanko pikepdf reportlab` y, opcionalmente, `pdfsig` (poppler-utils)

## Uso

### Compilar

```sh
scripts/build.sh              # genera build/sign (Bend -> C -> gcc), 4 hilos
TPC_L2=0 scripts/build.sh     # 1 hilo (2^TPC_L2 hilos)
```

### Firmar desde la línea de comandos

El programa trabaja con nombres de archivo fijos en el directorio actual:

| Archivo | |
|---|---|
| `input.pdf` | documento a firmar |
| `key.pem` | llave privada RSA (PEM o DER, PKCS#1 o PKCS#8 sin cifrar) |
| `cert.pem` | certificado del firmante; puede traer la cadena (firmante primero) |
| `params.txt` | opcional, `clave=valor` por línea (UTF-8) |
| `output.pdf` | resultado (o `error.txt` con el mensaje de error) |

Parámetros de `params.txt`: `name` (por defecto el CN del certificado),
`reason`, `location`, `contact`, `time` (UTC, `YYYYMMDDHHmmSS`) y `sig_size`
(bytes reservados para el CMS, 8192 por defecto).

```sh
mkdir trabajo && cd trabajo
cp documento.pdf input.pdf && cp mi_llave.pem key.pem && cp mi_cert.pem cert.pem
printf 'reason=Aprobación\nlocation=Santiago\ntime=20261023120000\n' > params.txt
../build/sign            # o: bend run-c ../sign.bend
```

### Servicio HTTP

```sh
scripts/build.sh
SIGN_KEY=/ruta/llave.pem SIGN_CERT=/ruta/cert.pem python3 service/server.py
```

| Método y ruta | Descripción |
|---|---|
| `GET /` | formulario web para probar la API |
| `GET /health` | estado |
| `POST /api/v1/sign` | firma síncrona; responde `{"pdf": "<base64>"}` o el PDF si `Accept: application/pdf` |
| `POST /api/v1/jobs` | firma asíncrona; responde `{"id": ...}` (202) |
| `GET /api/v1/jobs/<id>` | estado: `running`, `done` o `error` |
| `GET /api/v1/jobs/<id>/pdf` | PDF firmado |

Cuerpo JSON:

```json
{ "pdf": "<base64>", "reason": "Aprobación", "location": "Santiago", "contact": "", "name": "" }
```

```sh
curl -s -X POST localhost:8080/api/v1/sign \
  -H 'Content-Type: application/json' -H 'Accept: application/pdf' \
  -d "{\"pdf\": \"$(base64 -w0 documento.pdf)\", \"reason\": \"Aprobación\"}" \
  -o firmado.pdf
```

Configuración por variables de entorno (ver `service/server.py`):
`SIGN_HOST`, `SIGN_PORT`, `SIGN_BIN`, `SIGN_KEY`, `SIGN_CERT`,
`SIGN_API_TOKEN` (exige `Authorization: Bearer <token>`),
`SIGN_ALLOW_CLIENT_KEYS=1` (permite enviar `key`/`cert` en la petición;
desactivado por defecto: lo normal es que la llave viva en el servidor),
`SIGN_MAX_JOBS`, `SIGN_TIMEOUT`, `SIGN_SIG_SIZE`, `SIGN_JOB_TTL`.

El servicio escucha en `127.0.0.1` por defecto y no implementa TLS: en
producción debe ir detrás de un proxy inverso con HTTPS.

## Pruebas

```sh
python3 tests/gen_unit_tests.py && bend run-rs test.bend   # 55 pruebas unitarias -> (55, [])
python3 tests/make_fixtures.py                              # regenera los PDFs de prueba
tests/e2e.sh                                                # firma + validación (RSA-1024 temporal)
KEY_BITS=2048 tests/e2e.sh                                  # idem con RSA-2048
python3 tests/validate.py firmado.pdf raiz.pem              # valida un PDF con pyHanko y pdfsig
```

Los PDFs de prueba cubren tabla xref clásica, xref stream con object streams,
PDF linealizado, `/AcroForm` y `/Annots` indirectos con campos existentes, y
doble firma (actualizaciones incrementales encadenadas).

## Rendimiento

Medido en el contenedor de desarrollo (1 hilo, HVM C; el entorno tiene fallos
de página muy costosos, en hardware normal debería ser bastante más rápido):

| Operación | Interacciones HVM | Tiempo |
|---|---|---|
| Firma de un PDF pequeño, RSA-1024 | 255 M | 22 s |
| Firma de un PDF pequeño, RSA-2048 | 1 511 M | 77 s |
| SHA-256 de 256 KiB | 169 M (~41 k por bloque de 64 bytes) | 8–20 s |

La operación RSA domina. Las dos exponenciaciones del CRT son independientes y
HVM puede ejecutarlas en paralelo (`TPC_L2`); en este contenedor los hilos
extra no aportaron por el costo de los fallos de página.

## Limitaciones conocidas

- PDFs de hasta 16 MiB (las posiciones son `u24`).
- No se soportan PDFs cifrados ni llaves PKCS#8 cifradas.
- Firma invisible (sin apariencia); sólo RSA con SHA-256; sin sello de tiempo (PAdES B-T) ni datos de revocación (B-LT).
- Sólo se decodifica `/FlateDecode` (lo que usan los xref streams y object streams en la práctica).

## Lecciones sobre Bend 0.2 / HVM 2 (útiles para escribir más librerías)

- **Sólo hay enteros de 24 bits.** Palabras de 32 bits se representan como pares de 16 bits; los enteros grandes usan limbs de 12 bits porque `(2^12-1)^2 + 2(2^12-1) = 2^24-1` cabe exacto.
- **`IO/FS/read_file` del runtime C extiende el signo** de los bytes ≥ 0x80 (0x93 llega como 0xFFFF93): todo lo leído debe pasar por `Bytes/from_io`.
- **Expresiones cerradas que llaman funciones** se extraen como definiciones globales; si HVM debe duplicarlas antes de evaluarlas aborta con `attempt to clone a non-affine global reference`. Las constantes deben ser literales de datos (ver `Cms/ALG_SHA256`, `Pdf/lit`, `Pdf/null`).
- **`object` construido dentro de un módulo importado transitivamente** hace fallar al compilador (`order_kwargs`); se usa `type T: New {...}` en su lugar.
- Los imports se resuelven desde el directorio del archivo principal, por eso los programas (`sign.bend`, `test.bend`) están en la raíz.
- Mantener `main` delgado: la lógica pura fuera del bloque `with IO`.
- El costo dominante en HVM no es la aritmética sino recorrer estructuras: empaquetar datos (p. ej. `b_j | n_j << 12` en un solo `u24`) y recorrer una sola lista por paso redujo un 34 % el costo de Montgomery.

## Próximos pasos sugeridos

- Firma visible (apariencia `/AP` con texto e imagen).
- Sello de tiempo RFC 3161 (PAdES B-T) y LTV (B-LT/B-LTA).
- Firma remota/HSM usando la API en dos pasos de `lib/cms.bend`.
- ECDSA P-256 (llaves más pequeñas y firma más rápida que RSA en HVM).
- Validación de firmas en Bend (el código de verificación RSA ya existe).
