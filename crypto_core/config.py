"""
Configuración central de MailGuard PKI.
Modifica aquí los valores que aplican a todo el proyecto.
"""

from pathlib import Path

# URL pública desde donde los clientes de correo descargan el CRL.
# Se embebe en cada certificado de usuario al firmarlo (RFC 5280 §4.2.1.13).
# Cambiar antes de emitir certs para producción.
CRL_URL = "http://mailguard.ddns.net:8099/crl/inter-ca.crl"

# Password del rol Admin (Registration Authority operator).
# Cambiar a un valor fuerte antes de poner el sistema en producción.
ADMIN_PASSWORD = "MailGuardAdmin2026!"

# Ruta de la base de datos SQLite que actúa como Registration Authority.
# Persiste en el volumen ca_intermedia_output/ del docker-compose.
RA_DB_PATH = Path("ca_intermedia_output/ra.db")

# Configuración de la organización emisora (se usa en los certs de usuario).
ORG_DEFAULTS = {
    "country":  "MX",
    "state":    "Estado de Mexico",
    "locality": "Huixquilucan",
    "org":      "Universidad Anahuac",
}
