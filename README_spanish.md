# GhostPay Solana

Implementación orientada a seguridad de un flujo de pagos con notas privadas en Solana usando Anchor, bóvedas SPL Token, semántica de commit/reveal, nullifiers y gasto de bóveda autorizado por PDA.

Este documento está escrito para revisores de seguridad y auditores.

## 1. Resumen Ejecutivo

GhostPay Solana implementa un modelo de notas con preservación de privacidad donde:

1. El emisor compromete receptor y monto usando compromisos hash.
2. Los compromisos están vinculados a un hash de secreto compartido derivado por ECDH fuera de cadena.
3. Los fondos pueden depositarse en una bóveda SPL durante la creación de la nota.
4. El gasto requiere una prueba privada de apertura de propiedad y un nullifier único.
5. Los retiros de bóveda son autorizados por un firmante PDA derivado por programa.

El objetivo de diseño es reforzar privacidad de forma práctica en un ledger transparente, manteniendo restricciones explícitas anti-doble-gasto y verificaciones estrictas de vinculación de cuentas.

## 2. Alcance del Repositorio

Programa principal on-chain:

- [src/lib.rs](src/lib.rs)

Prototipos de cliente e interfaz:

- [client/client.ts](client/client.ts)
- [frontend/index.html](frontend/index.html)
- [frontend/styles.css](frontend/styles.css)
- [frontend/app.js](frontend/app.js)

Pruebas del programa:

- [tests/anchor.test.ts](tests/anchor.test.ts)

## 3. Objetivos de Seguridad

Objetivos primarios:

1. Confidencialidad del vínculo con el receptor y del monto antes del reveal.
2. Anti-replay y anti-doble-gasto mediante unicidad de nullifier.
3. Autorización de gasto por prueba de conocimiento, no por identidad simple.
4. Movimiento controlado de bóveda mediante seeds de PDA firmante y restricciones de cuentas.
5. Ruta de gasto determinística y auditable.

Objetivos secundarios:

1. Soportar reveal selectivo para flujos de auditoría/compliance.
2. Mantener el estado del protocolo compacto y explícito.

No objetivos (versión actual):

1. Garantías completas de conjunto de anonimato con zero-knowledge.
2. Privacidad a nivel mempool.
3. Desvinculación completa a nivel de red.
4. Endurecimiento de producción contra todas las clases de side-channel.

## 4. Arquitectura de Alto Nivel

Componentes del sistema:

1. Programa Anchor on-chain
: Almacena notas, verifica aperturas de reveal, impone unicidad de nullifier y controla gastos de bóveda.
2. Derivación criptográfica off-chain
: Deriva el hash de secreto compartido (estilo ECDH) y las entradas de compromiso.
3. Bóveda SPL Token
: Mantiene fondos comprometidos hasta ejecución de gasto válida.
4. Frontend y cliente
: Generan compromisos, calculan nullifiers, realizan matching local por scan y envían transacciones.

Límites de confianza:

1. El estado del programa y balances SPL son la verdad confiable on-chain.
2. La lógica de derivación off-chain se confía solo como productora de entradas; todas las verificaciones críticas se revalidan on-chain cuando aplica.
3. El entorno de firma de la wallet debe ser confiable por el usuario.

## 5. Vista General del Protocolo

### 5.1 Crear Nota (Commit)

Entradas:

1. hashed_recipient (32 bytes)
2. amount_commitment (32 bytes)
3. ephemeral_pubkey (32 bytes)
4. scan_tag (32 bytes)
5. spend_auth_commitment (32 bytes)
6. nonce (u64)

Ruta opcional con bóveda:

1. Transferencia SPL desde la cuenta de token del firmante hacia la cuenta de token de bóveda.
2. Persistencia en estado de la cuenta de bóveda, PDA de autoridad de bóveda y vínculo con mint.

### 5.2 Reveal

Entradas:

1. recipient
2. recipient_blinding
3. shared_secret_hash
4. amount
5. amount_blinding

Verificaciones on-chain:

1. Recalcular compromiso de receptor y comparar con hashed_recipient almacenado.
2. Recalcular compromiso de monto y comparar con amount_commitment almacenado.
3. Recalcular scan_tag desde ephemeral_pubkey y shared_secret_hash.

### 5.3 Consumo de Nullifier

Entradas:

1. nullifier
2. spend_auth_opening

Verificaciones on-chain:

1. La nota aún no está gastada.
2. ownership_commitment == hash(note_pubkey || spend_auth_opening).
3. nullifier == hash(note_pubkey || spend_auth_opening || "nullifier").
4. El PDA de nullifier se inicializa exactamente una vez.

### 5.4 Gasto Seguro desde Bóveda

Entradas:

1. nullifier
2. spend_auth_opening
3. withdraw_amount

Verificaciones on-chain:

1. La nota no está gastada.
2. vault_token_account coincide con el estado de la nota.
3. vault_authority PDA coincide con el estado de la nota.
4. token_mint coincide con el estado de la nota.
5. withdraw_amount debe ser igual al monto completo en bóveda de la nota (regla actual).
6. Pasan las verificaciones de prueba de propiedad y derivación de nullifier.

Ejecución:

1. Inicializar registro de nullifier.
2. Transferir SPL desde vault token account hacia recipient token account usando seeds de PDA firmante.
3. Marcar la nota como gastada y setear vault_deposit_amount en cero.

## 6. Diseño Criptográfico

### 6.1 Vinculación por Secreto Compartido

ECDH off-chain (estilo X25519 en prototipo cliente/test) deriva secreto compartido, luego:

$$
shared\_secret\_hash = H(shared\_secret || nonce)
$$

Este hash vincula los cálculos de reveal y scan al contexto de acuerdo de claves emisor/receptor.

### 6.2 Compromiso de Receptor

$$
hashed\_recipient = H(recipient || recipient\_blinding || shared\_secret\_hash)
$$

### 6.3 Compromiso de Monto

$$
amount\_commitment = H(amount\_{le\_u64} || amount\_blinding || shared\_secret\_hash)
$$

### 6.4 Scan Tag

$$
scan\_tag = H(ephemeral\_pubkey || shared\_secret\_hash)
$$

### 6.5 Compromiso de Autorización de Gasto

$$
spend\_auth\_commitment = H(note\_pubkey || spend\_auth\_opening)
$$

### 6.6 Nullifier

$$
nullifier = H(note\_pubkey || spend\_auth\_opening || "nullifier")
$$

La unicidad de nullifier se impone por inicialización de PDA bajo el prefijo de seed nullifier.

## 7. Modelo de Estado

Cuenta principal: GhostPayment

1. payer
2. hashed_recipient
3. amount_commitment
4. ephemeral_pubkey
5. scan_tag
6. spend_auth_commitment
7. nonce
8. campos de reveal
9. vault_token_account
10. vault_authority
11. token_mint
12. vault_deposit_amount
13. spent

Cuenta auxiliar: NullifierRecord

1. nullifier
2. ghost_payment
3. owner
4. created_at_slot

## 8. Controles de Seguridad e Invariantes

### 8.1 Anti-Doble-Gasto

Control:

1. Bandera spent en la nota.
2. Semántica init-once del PDA NullifierRecord.

Invariante:

1. Un nullifier solo puede consumirse una vez.
2. Una nota marcada como gastada no puede volver a gastarse.

### 8.2 Integridad de Bóveda

Control:

1. Verificaciones de vínculo de mint.
2. Verificaciones de propiedad de cuenta de bóveda.
3. Vinculación de autoridad de bóveda al estado de nota.
4. Seeds de PDA firmante para autorización de transferencia SPL.

Invariante:

1. El programa solo gasta desde la bóveda exacta y mint registrado en el estado de la nota.

### 8.3 Privacidad de Autorización de Gasto

Control:

1. La ruta de gasto valida opening proof contra spend_auth_commitment.

Invariante:

1. La posesión de identidad de firmante por sí sola no autoriza gasto.

### 8.4 Integridad de Reveal

Control:

1. Verificaciones de apertura de receptor y monto.
2. Verificación de consistencia de shared_secret_hash vía scan_tag.

Invariante:

1. Valores de apertura inválidos son rechazados.

## 9. Modelo de Amenazas

### Amenazas En Alcance

1. Intentos de doble gasto mediante nullifier reusado.
2. Retiros de bóveda no autorizados por enrutamiento de cuentas forjado.
3. Datos de reveal inválidos para forjar apertura de compromiso.
4. Replay cross-note de autorizaciones de gasto.

### Fuera de Alcance o Mitigadas Parcialmente

1. Anonimato completo contra análisis global de tráfico.
2. Compromiso del endpoint de wallet/navegador/dispositivo.
3. Fugas side-channel en librerías criptográficas off-chain.
4. Fuga de metadatos por timing de transacciones y comportamiento de fees.

## 10. Notas de Seguridad por Instrucción

API on-chain en [src/lib.rs](src/lib.rs):

1. create_ghost_payment
: Compromete campos de nota sin movimiento de tokens.
2. create_ghost_payment_with_vault
: Compromete nota y deposita SPL en bóveda.
3. reveal_payment
: Verifica aperturas de compromiso y vinculación por secreto compartido.
4. consume_nullifier
: Consume nullifier con prueba privada de apertura.
5. spend_from_vault
: Ejecuta retiro seguro de bóveda con seeds de PDA firmante.

## 11. Testing y Verificación

Pruebas de referencia en [tests/anchor.test.ts](tests/anchor.test.ts):

1. Ruta commit y reveal con derivación de secreto compartido estilo ECDH.
2. Consumo de nullifier y transición de estado spent.
3. Depósito en bóveda usando mint SPL y ATAs.
4. Gasto desde cuenta controlada por PDA hacia ATA de receptor.

Pruebas adicionales recomendadas para preparación formal de auditoría:

1. Gasto negativo con spend_auth_opening incorrecto.
2. Intento de replay de nullifier.
3. Pruebas de rechazo por mint mismatch y vault account mismatch.
4. Fuzzing para arreglos de 32 bytes malformados y valores límite de u64.
5. Property tests que garanticen unicidad de nullifier con openings aleatorios.

## 12. Checklist de Seguridad Operacional

Antes de despliegue en producción:

1. Congelar y versionar domain separators criptográficos.
2. Agregar domain tags explícitos a todos los hashes para reducir riesgo de colisión cross-context.
3. Introducir autorización de gasto basada en circuitos o pruebas para mayor privacidad.
4. Agregar monitoreo rate-limited para fallas sospechosas de nullifier.
5. Ejecutar auditoría externa y pruebas diferenciales contra un modelo de referencia.
6. Revisar comportamiento de compute budget bajo empaquetado adversarial de transacciones.
7. Fijar versiones de dependencias y verificar builds reproducibles.

## 13. Limitaciones Actuales

1. Se aplica actualmente regla de gasto total de nota para gastos de bóveda.
2. Aún no se integra un sistema zk-proof.
3. El frontend incluye rutas demo locales y no es una interfaz de custodia para producción.
4. La privacidad sigue siendo probabilística bajo análisis de metadatos en ledger público.

## 14. Notas de Seguridad del Frontend

La UI prototipo se encuentra en:

1. [frontend/index.html](frontend/index.html)
2. [frontend/styles.css](frontend/styles.css)
3. [frontend/app.js](frontend/app.js)

El frontend actualmente demuestra lógica local de compromiso y UX de flujo. Las validaciones críticas de seguridad permanecen on-chain.

## 15. Build y Ejecución Local

Preview estático del frontend:

```bash
python3 -m http.server 8080
```

Abrir:

```url
http://localhost:8080/frontend/
```

La ejecución del programa y pruebas depende del entorno Anchor/Solana Playground y la configuración del proyecto.

## 16. Contacto de Auditoría y Política de Divulgación

Política sugerida para este repositorio:

1. Reportar vulnerabilidades de forma privada primero a los mantenedores.
2. Incluir prueba de concepto, impacto e instrucción(es) afectada(s).
3. Permitir ventana de divulgación coordinada antes del reporte público.

Hasta agregar una política formal en archivo dedicado, tratar hallazgos como confidenciales por defecto.
