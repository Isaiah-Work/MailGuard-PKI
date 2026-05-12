"""
Configuración central de MailGuard PKI.
Modifica aquí los valores que aplican a todo el proyecto.
"""

import os
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

# ──────────────────────────────────────────────────────────
#  Active Directory (sincronizacion batch — Modo A)
# ──────────────────────────────────────────────────────────
# Credenciales de la cuenta de servicio que consulta el DC de la Anahuac.
# AD_PASSWORD debe venir de variable de entorno; el valor aqui es un placeholder
# que se pisa en produccion.
AD_CONFIG = {
    "enabled":       False,
    "server":        "ldap://dc.anahuac.mx",
    "base_dn":       "DC=anahuac,DC=mx",
    "user_dn":       "CN=svc_mailguard,OU=ServiceAccounts,DC=anahuac,DC=mx",
    "password":      os.environ.get("AD_PASSWORD"),
    "domain_suffix": "anahuac.mx",
    # Filtro LDAP que selecciona los usuarios a sincronizar.
    # Ajustar el memberOf segun la estructura de grupos de la Anahuac.
    "user_filter": (
        "(&(objectClass=user)"
        "(mail=*@anahuac.mx)"
        "(memberOf=CN=Alumnos,OU=Groups,DC=anahuac,DC=mx))"
    ),
}

# Umbrales (en dias) para clasificar la urgencia de expiracion de un cert.
# Cualquier cert por encima del mayor umbral se considera "ok" (verde).
EXPIRY_THRESHOLDS_DAYS = {
    "urgent":  7,    # rojo: vence en menos de 7 dias
    "warning": 15,   # naranja: vence en 7-15 dias
    "notice":  30,   # amarillo: vence en 15-30 dias
}
