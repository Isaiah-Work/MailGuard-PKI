"""
Configuración central de MailGuard PKI.
Modifica aquí los valores que aplican a todo el proyecto.
"""

# URL pública desde donde los clientes de correo descargan el CRL.
# Se embebe en cada certificado de usuario al firmarlo (RFC 5280 §4.2.1.13).
# Cambiar antes de emitir certs para producción.
CRL_URL = "http://mailguard.ddns.net:8099/crl/inter-ca.crl"
