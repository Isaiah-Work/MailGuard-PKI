# Proyecto: Sistema de Seguridad en Correo Electrónico (PKI)

## 📋 Descripción General
Este proyecto tiene como objetivo diseñar e implementar un sistema de seguridad para correo electrónico basado en una **Infraestructura de Clave Pública (PKI)**. 

La meta principal es establecer un flujo de comunicación seguro que garantice:
1.  **Identidad (Autenticación):** Confirmar que el remitente es quien dice ser.
2.  **Integridad:** Asegurar que el mensaje no ha sido modificado en el camino.
3.  **Confidencialidad:** Encriptar el mensaje para que solo el destinatario pueda leerlo.

El sistema final deberá integrarse y funcionar dentro de un cliente de correo real (**Outlook**).

---

## 📅 Fases del Proyecto (Roadmap)

El desarrollo se dividirá en tres grandes hitos:

### Fase 1: Fundamentos de PKI (Infraestructura de Clave Pública)
Investigación y base teórica. Se debe comprender cómo funciona la confianza en la red.
* **Preguntas clave a resolver:**
    * ¿Qué es una jerarquía de confianza?
    * ¿Cuál es la diferencia entre una Autoridad de Certificación (CA) y una Autoridad de Registro (RA)?
    * ¿Qué es la revocación de certificados (CRL/OCSP)?

### Fase 2: Certificados Digitales y Estándares
Definición de las reglas del juego y los formatos de archivo.
* **Formatos:** Identificar extensiones y estructuras (ej. X.509, .pem, .crt, .p12).
* **Emisión:** Proceso de generación de CSR (Certificate Signing Request) y firma por parte de la CA.
* **Autoridades:** Identificar quiénes son las CA confiables y cómo crear una CA propia para pruebas.

### Fase 3: Conexión con Outlook e Implementación
Puesta en marcha del sistema criptográfico en un entorno real.
* **Integración:** Configuración de S/MIME en Outlook.
* **Gestión de Claves:** Importación de llaves públicas y privadas en el sistema operativo (Windows Certificate Store).

---

## ⚙️ Proceso Técnico y Arquitectura

### 1. Actores del Sistema
* **🛡️ Autoridad Certificadora (CA):** Entidad de confianza que emite y firma los certificados.
* **👤 Remitente (Cliente 1):** Quien redacta, firma y cifra el correo.
* **📩 Destinatario (Cliente 2 - Outlook):** Quien recibe, descifra y verifica la firma.

### 2. Algoritmos Criptográficos (Matemáticas Discretas)
Utilizaremos un **Cifrado Híbrido** para combinar eficiencia y seguridad:

* **Cifrado Simétrico (Para el contenido del mensaje):**
    * **AES (Advanced Encryption Standard):** Se usará para cifrar el cuerpo del correo debido a su alta velocidad.
* **Cifrado Asimétrico (Para claves y firmas):**
    * **RSA (2048 bits):** Estándar clásico para intercambio de claves.
    * **ECC (Elliptic Curve Cryptography):**
        * *ECDSA / EdDSA:* Para firmas digitales más eficientes.
        * *Curvas NIST (P-256, etc.):* Estándares matemáticos aprobados para la generación de claves.

### 3. Flujo de un Correo Seguro
El ciclo de vida de un mensaje en nuestro sistema será:

1.  **Firma Digital:** El Remitente usa su **Clave Privada** para firmar el hash del mensaje (Garantiza Identidad + Integridad).
2.  **Encriptación (Sobre Digital):**
    * El mensaje se cifra con una clave temporal **AES**.
    * La clave AES se cifra con la **Clave Pública** del Destinatario.
3.  **Envío:** El paquete cifrado viaja por internet.
4.  **Recepción (Outlook):**
    * El Destinatario usa su **Clave Privada** para descifrar la clave AES.
    * Usa la clave AES para leer el mensaje.
    * Usa la **Clave Pública** del Remitente para verificar la firma.

---

## 🚀 PRIMERA ENTREGA: Investigación y Marco Teórico

**Objetivo:** Establecer las bases conceptuales del proyecto. La entrega debe cubrir los siguientes puntos de manera detallada:

### A. Definición de PKI
Explicar qué es una Public Key Infrastructure y desglosar sus componentes principales:
* **CA (Certificate Authority):** El "notario" digital.
* **RA (Registration Authority):** Quien verifica la identidad antes de emitir el certificado.
* **Usuario Final (End Entity):** Personas o servidores que usan los certificados.
* **Repositorio:** Donde se guardan los certificados y las listas de revocación.

### B. Análisis de Algoritmos
Comparativa técnica enfocada en nuestro caso de uso:
1.  **RSA vs. Curvas Elípticas (ECC):**
    * Comparar longitud de claves (ej. RSA-2048 vs ECC-256).
    * Eficiencia computacional (¿Cuál firma más rápido?).
    * Diferencia entre ECDSA y EdDSA (Ed25519).
2.  **Cifrado Híbrido:**
    * Justificación: ¿Por qué usamos **AES** para el mensaje y RSA/ECC para las firmas? (Explicar la relación Costo Computacional vs. Seguridad).

### C. Estándares y Normativas
* **Certificados Digitales:** ¿Qué es el estándar **X.509**? (Explicar su estructura básica: Versión, Serial Number, Signature Algorithm, Issuer, Subject, Public Key Info).
* **NIST:** Investigar el rol del *National Institute of Standards and Technology* en la estandarización de las curvas elípticas seguras.

### D. Resumen Ejecutivo
* Definición concisa de PKI en sus propias palabras.
* 2 Ejemplos de uso de PKI en la vida real (fuera del correo electrónico, ej: HTTPS, DNI electrónico).
