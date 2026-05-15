"""
Conector LDAP/Active Directory para sincronizacion de identidades
con la Registration Authority (RA) de MailGuard PKI.

Modo A (batch): el admin dispara una sincronizacion periodica contra el
Directorio Activo de la Anahuac.  Los usuarios se enrolan automaticamente
en la RA local con una password temporal.  La autenticacion sigue siendo
local (no se delega al DC), manteniendo bajo acoplamiento entre sistemas.
"""

import secrets
from typing import Any

from ldap3 import ALL, SUBTREE, Connection, Server

from crypto_core.config import AD_CONFIG


def _ad_connect() -> Connection:
    """Abre una conexion al DC y hace bind con la cuenta de servicio."""
    server = Server(AD_CONFIG["server"], get_info=ALL)
    conn = Connection(
        server,
        user=AD_CONFIG["user_dn"],
        password=AD_CONFIG["password"],
        auto_bind=True,
    )
    return conn


def _ad_entry_to_dict(entry: Any) -> dict:
    """Convierte una entrada LDAP a un dict plano con los campos que la RA necesita."""
    return {
        "email": str(entry.mail).strip() if entry.mail else "",
        "cn": str(entry.cn).strip() if entry.cn else "",
        "display_name": str(entry.displayName).strip() if entry.displayName else "",
        "nombre": _pick_nombre(entry),
        "org_unit": _pick_org_unit(entry),
        "sAMAccountName": str(entry.sAMAccountName).strip() if entry.sAMAccountName else "",
        "object_guid": _guid_to_str(entry.objectGUID) if entry.objectGUID else "",
        "user_account_control": int(entry.userAccountControl.value) if entry.userAccountControl else 0,
    }


def _pick_nombre(entry: Any) -> str:
    """Selecciona el mejor campo para el CN del certificado (displayName > cn)."""
    if entry.displayName:
        return str(entry.displayName).strip()
    if entry.cn:
        return str(entry.cn).strip()
    return ""


def _pick_org_unit(entry: Any) -> str:
    """Mapea department de AD a org_unit de RA.  Cae a 'Alumnos' si no hay."""
    if entry.department:
        return str(entry.department).strip()
    return "Alumnos"


def _guid_to_str(guid_bytes: bytes | str) -> str:
    """Convierte objectGUID (binario) a hexadecimal legible."""
    if isinstance(guid_bytes, bytes):
        return guid_bytes.hex()
    return str(guid_bytes)


def _uac_disabled(uac: int) -> bool:
    """True si el flag ACCOUNTDISABLE (bit 1) esta encendido."""
    return bool(uac & 2)


def _update_ra_user(email: str, nombre: str, org_unit: str):
    """Actualiza nombre y org_unit de un usuario existente en RA."""
    from crypto_core.ra import _connect, init_db

    init_db()
    conn = _connect()
    try:
        conn.execute(
            "UPDATE usuarios SET nombre = ?, org_unit = ? WHERE email = ?",
            (nombre, org_unit, email),
        )
        conn.commit()
    finally:
        conn.close()


def query_ad_user(email: str) -> dict | None:
    """Busca un usuario en AD por email canonico.  Devuelve dict o None."""
    conn = _ad_connect()
    try:
        filter_str = f"(&(objectClass=user)(mail={email}))"
        conn.search(
            search_base=AD_CONFIG["base_dn"],
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=[
                "mail", "cn", "displayName", "department",
                "sAMAccountName", "objectGUID", "userAccountControl",
            ],
        )
        if not conn.entries:
            return None
        return _ad_entry_to_dict(conn.entries[0])
    finally:
        conn.unbind()


def sync_ad_to_ra(dry_run: bool = False) -> dict:
    """
    Sincroniza usuarios desde AD hacia la tabla usuarios de RA.

    Reglas:
    - Usuarios en AD con cuenta deshabilitada → se omiten.
    - Usuarios en AD que NO existen en RA → se enrolan con password temporal.
    - Usuarios en AD que YA existen en RA → se actualiza nombre / org_unit si
      cambiaron (sin tocar password ni filename).
    - Usuarios en RA que ya NO estan en AD → NO se tocan (baja manual).

    Devuelve un dict con el resumen de la operacion.
    """
    if not AD_CONFIG["enabled"]:
        return {"created": 0, "updated": 0, "skipped": 0, "errors": ["AD no esta habilitado (AD_CONFIG['enabled'] = False)."]}

    if not AD_CONFIG["password"]:
        return {"created": 0, "updated": 0, "skipped": 0, "errors": ["AD_CONFIG['password'] no configurado."]}

    from crypto_core.ra import enroll_user, list_users

    conn = _ad_connect()
    summary: dict[str, Any] = {"created": 0, "updated": 0, "skipped": 0, "errors": []}

    try:
        filter_str = AD_CONFIG.get(
            "user_filter",
            f"(&(objectClass=user)(mail=*@{AD_CONFIG['domain_suffix']}))",
        )
        conn.search(
            search_base=AD_CONFIG["base_dn"],
            search_filter=filter_str,
            search_scope=SUBTREE,
            attributes=[
                "mail", "cn", "displayName", "department",
                "sAMAccountName", "objectGUID", "userAccountControl",
            ],
        )

        if not conn.entries:
            summary["errors"].append("La consulta LDAP no devolvio ningun usuario.")
            return summary

        ad_users = [_ad_entry_to_dict(e) for e in conn.entries]
        ra_users = {u["email"]: u for u in list_users()}

        for ad_u in ad_users:
            email = ad_u["email"]
            if not email:
                summary["skipped"] += 1
                continue

            if _uac_disabled(ad_u.get("user_account_control", 0)):
                summary["skipped"] += 1
                continue

            nombre = ad_u["nombre"]
            org_unit = ad_u["org_unit"]

            try:
                if email in ra_users:
                    existing = ra_users[email]
                    if existing["nombre"] != nombre or existing["org_unit"] != org_unit:
                        if not dry_run:
                            _update_ra_user(email, nombre, org_unit)
                        summary["updated"] += 1
                    else:
                        summary["skipped"] += 1
                else:
                    if not dry_run:
                        temp_password = secrets.token_urlsafe(16)
                        enroll_user(
                            email=email,
                            nombre=nombre,
                            org_unit=org_unit,
                            user_password=temp_password,
                            enrolled_by="ad_sync",
                        )
                    summary["created"] += 1
            except Exception as e:
                summary["errors"].append(f"{email}: {e}")

    finally:
        conn.unbind()

    return summary
