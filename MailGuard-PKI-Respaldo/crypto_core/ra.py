"""
Registration Authority (RA) -- pre-registro de identidades y autenticacion
de solicitudes de certificado.

Modelo arquitectonico:
- El admin enrola usuarios en SQLite con su password personal (hash scrypt).
- El admin "desbloquea" la CA una vez por sesion ingresando inter_password
  y master_password; quedan cacheados en memoria del proceso.
- Los usuarios se auto-sirven en /solicitar autenticando con email + password
  personal. La RA verifica credenciales y la CA emite el cert usando los
  passwords cacheados.

Aislamiento de roles:
- El usuario nunca conoce inter_password ni master_password.
- El admin nunca conoce el password personal del usuario (solo hashes).
- Si el proceso se reinicia, la CA queda bloqueada hasta nuevo unlock.
"""

import hashlib
import re
import secrets
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from crypto_core.config import ADMIN_PASSWORD, EXPIRY_THRESHOLDS_DAYS, RA_DB_PATH

# Parametros de scrypt -- recomendados por OWASP para password hashing.
SCRYPT_N = 2 ** 14   # CPU/memoria
SCRYPT_R = 8         # block size
SCRYPT_P = 1         # parallelization
SCRYPT_DKLEN = 32    # bytes de salida

# Cache de sesion para los passwords de la CA. Se llena con admin_unlock()
# y se vacia con admin_lock() o reinicio del proceso.
_session = {}


# ──────────────────────────────────────────────────────────
#  Inicializacion de la base de datos
# ──────────────────────────────────────────────────────────
def _connect():
    RA_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(RA_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Crea las tablas si no existen. Idempotente. Tambien aplica migraciones."""
    conn = _connect()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT NOT NULL UNIQUE,
            nombre          TEXT NOT NULL,
            filename        TEXT NOT NULL UNIQUE,
            org_unit        TEXT NOT NULL DEFAULT 'Alumnos',
            password_hash   BLOB NOT NULL,
            salt            BLOB NOT NULL,
            enrolled_at     TEXT NOT NULL,
            enrolled_by     TEXT,
            status          TEXT NOT NULL DEFAULT 'active',
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            last_request_at TEXT
        );

        CREATE TABLE IF NOT EXISTS cert_emissions (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            issued_at    TEXT NOT NULL,
            issued_ip    TEXT,
            filename     TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES usuarios(id)
        );
                       
        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha       TEXT NOT NULL,
            evento      TEXT NOT NULL,
            usuario_id  INTEGER,
            detalles    TEXT,
            ip_origen   TEXT,
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        );
    """)

    # Migraciones para soporte de expiracion / renovacion / validacion.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(cert_emissions)").fetchall()]
    if "expires_at" not in cols:
        conn.execute("ALTER TABLE cert_emissions ADD COLUMN expires_at TEXT")
    if "serial" not in cols:
        conn.execute("ALTER TABLE cert_emissions ADD COLUMN serial TEXT")
    if "status" not in cols:
        conn.execute("ALTER TABLE cert_emissions ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
    if "superseded_by" not in cols:
        conn.execute("ALTER TABLE cert_emissions ADD COLUMN superseded_by INTEGER")
    if "validation_status" not in cols:
        conn.execute("ALTER TABLE cert_emissions ADD COLUMN validation_status TEXT DEFAULT 'unchecked'")
    if "validation_at" not in cols:
        conn.execute("ALTER TABLE cert_emissions ADD COLUMN validation_at TEXT")

    conn.commit()
    conn.close()


# ──────────────────────────────────────────────────────────
#  Hashing de passwords
# ──────────────────────────────────────────────────────────
def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )


# ──────────────────────────────────────────────────────────
#  Derivacion de filename a partir del email
# ──────────────────────────────────────────────────────────
def email_to_filename(email: str) -> str:
    """
    Deriva un filename seguro para FS desde el local-part del email.
    Ej: 'jaime.chumacero@anahuac.mx' -> 'jaime_chumacero'
    """
    local = email.strip().lower().split("@")[0]
    cleaned = re.sub(r"[^a-z0-9]+", "_", local).strip("_")
    if not cleaned:
        raise ValueError(f"Email '{email}' no produce un filename valido.")
    return cleaned


# ──────────────────────────────────────────────────────────
#  Verificacion de admin
# ──────────────────────────────────────────────────────────
def verify_admin(admin_password: str) -> bool:
    return secrets.compare_digest(admin_password, ADMIN_PASSWORD)


# ──────────────────────────────────────────────────────────
#  Sesion online de la CA (unlock/lock)
# ──────────────────────────────────────────────────────────
def admin_unlock(admin_password: str, inter_password: str, master_password: str):
    """Desbloquea la CA cacheando los passwords en memoria del proceso."""
    if not verify_admin(admin_password):
        raise PermissionError("Admin password incorrecto.")

    # Sanity-check del master contra el escrow ya inicializado.
    from crypto_core.escrow import MASTER_CHECK, verify_master
    if MASTER_CHECK.exists() and not verify_master(master_password):
        raise ValueError("Master password de escrow incorrecto.")

    _session["inter"] = inter_password
    _session["master"] = master_password
    _session["since"] = datetime.utcnow().isoformat() + "Z"

    # Inyección: Registrar desbloqueo
    registrar_evento("CA_DESBLOQUEADA",detalles="El administrador ingresó las contraseñas maestras")


def admin_lock():
    """Olvida los passwords cacheados. Tras esto, /solicitar deja de funcionar."""
    _session.clear()
    
    # Inyección: Registrar bloqueo
    registrar_evento("CA_BLOQUEADA", detalles="Sesión administrativa cerrada manualmente")


def is_unlocked() -> bool:
    return "inter" in _session


def session_info() -> dict | None:
    return dict(_session) if _session else None


def get_session_passwords() -> tuple[str, str]:
    if not is_unlocked():
        raise RuntimeError(
            "La CA no esta desbloqueada. El admin debe desbloquearla primero "
            "ingresando inter_password y master_password."
        )
    return _session["inter"], _session["master"]


# ──────────────────────────────────────────────────────────
#  Enrolamiento (admin)
# ──────────────────────────────────────────────────────────
def enroll_user(
    email: str,
    nombre: str,
    org_unit: str,
    user_password: str,
    enrolled_by: str = "admin",
) -> dict:
    """Registra un nuevo usuario en la RA. Devuelve el dict del usuario creado."""
    init_db()
    filename = email_to_filename(email)

    if len(user_password) < 8:
        raise ValueError("La password personal debe tener al menos 8 caracteres.")

    salt = secrets.token_bytes(16)
    pw_hash = _hash(user_password, salt)
    now = datetime.utcnow().isoformat() + "Z"

    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO usuarios (email, nombre, filename, org_unit,
                                  password_hash, salt, enrolled_at, enrolled_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (email, nombre, filename, org_unit, pw_hash, salt, now, enrolled_by),
        )
        conn.commit()

        # Inyección: Registrar el alta del alumno
        registrar_evento("USUARIO_ENROLADO", detalles=f"Email: {email}, OU: {org_unit}")

        return {
            "id": cur.lastrowid,
            "email": email,
            "nombre": nombre,
            "filename": filename,
            "org_unit": org_unit,
        }
    except sqlite3.IntegrityError as e:
        if "email" in str(e):
            raise ValueError(f"Ya existe un usuario con email {email}.")
        if "filename" in str(e):
            raise ValueError(
                f"Ya existe un usuario con filename derivado '{filename}'. "
                "Otro email distinto produjo el mismo filename."
            )
        raise
    finally:
        conn.close()


def list_users() -> list[dict]:
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT id, email, nombre, filename, org_unit, status,
                   enrolled_at, last_request_at, failed_attempts
            FROM usuarios
            ORDER BY enrolled_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def list_emissions() -> list[dict]:
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT e.id, e.issued_at, e.issued_ip, e.filename,
                   u.email, u.nombre
            FROM cert_emissions e
            JOIN usuarios u ON u.id = e.user_id
            ORDER BY e.issued_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────
#  Verificacion del usuario (gate de /solicitar)
# ──────────────────────────────────────────────────────────
def authenticate_user(email: str, user_password: str) -> dict:
    """
    Verifica las credenciales del usuario contra la RA.
    Devuelve el dict del usuario si todo OK, levanta excepcion si no.

    Aplica:
      - Lockout despues de 5 intentos fallidos.
      - Marca last_request_at en exito.
      - Comparacion en tiempo constante.
    """
    init_db()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM usuarios WHERE email = ?", (email,)
        ).fetchone()
        if not row:
            raise PermissionError("Credenciales invalidas.")

        if row["status"] != "active":
            raise PermissionError(f"Cuenta no activa (status={row['status']}).")

        if row["failed_attempts"] >= 5:
            raise PermissionError(
                "Cuenta bloqueada por demasiados intentos fallidos. "
                "Contacta al admin."
            )

        expected = bytes(row["password_hash"])
        actual = _hash(user_password, bytes(row["salt"]))

        if not secrets.compare_digest(expected, actual):
            conn.execute(
                "UPDATE usuarios SET failed_attempts = failed_attempts + 1 WHERE id = ?",
                (row["id"],),
            )
            conn.commit()

            #Inyección: Registrar alerta de seguridad
            registrar_evento("LOGIN_FALLADO", usuario_id=row["id"], detalles="Contraseña personal incorrecta")

            raise PermissionError("Credenciales invalidas.")

        conn.execute(
            "UPDATE usuarios SET failed_attempts = 0, last_request_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat() + "Z", row["id"]),
        )
        conn.commit()
        return dict(row)
    finally:
        conn.close()


def record_emission(
    user_id: int,
    filename: str,
    expires_at: str | None = None,
    serial: str | None = None,
    ip: str | None = None,
    supersedes: int | None = None,
) -> int:
    """
    Registra una emision en la bitacora.

    Si supersedes es el ID de una emision previa, esa emision queda marcada
    con status='superseded' y superseded_by apuntando a la emision nueva.
    Devuelve el ID de la nueva emision.
    """
    init_db()
    conn = _connect()
    try:
        cur = conn.execute(
            """
            INSERT INTO cert_emissions
                (user_id, issued_at, issued_ip, filename, expires_at, serial, status)
            VALUES (?, ?, ?, ?, ?, ?, 'active')
            """,
            (
                user_id,
                datetime.utcnow().isoformat() + "Z",
                ip,
                filename,
                expires_at,
                serial,
            ),
        )
        new_id = cur.lastrowid

        if supersedes is not None:
            conn.execute(
                """
                UPDATE cert_emissions
                SET status = 'superseded', superseded_by = ?
                WHERE id = ?
                """,
                (new_id, supersedes),
            )

        conn.commit()

        #Inyección: Registrar emisión y ligar al usuario y su IP
        registrar_evento("CERTIFICADO_EMITIDO", usuario_id=user_id, detalles=f"Serial: {serial}", ip=ip)

        return new_id
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────
#  Expiracion y renovacion
# ──────────────────────────────────────────────────────────
def extract_cert_metadata(cert_path: Path | str) -> dict:
    """Lee un cert X.509 (PEM) y extrae su serial y fecha de expiracion."""
    cert_path = str(cert_path)

    serial_out = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-serial"],
        capture_output=True, text=True, check=True,
    ).stdout
    serial = serial_out.split("=", 1)[1].strip()

    enddate_out = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
        capture_output=True, text=True, check=True,
    ).stdout
    raw = enddate_out.split("=", 1)[1].strip()  # "Apr 29 14:00:00 2027 GMT"
    no_tz = raw.rsplit(" ", 1)[0]
    dt = datetime.strptime(no_tz, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)

    return {"serial": serial, "expires_at": dt.isoformat()}


def days_until(expires_at_iso: str | None) -> int | None:
    """Dias restantes hasta la expiracion. Negativo si ya expiro. None si desconocido."""
    if not expires_at_iso:
        return None
    expires = datetime.fromisoformat(expires_at_iso.replace("Z", "+00:00"))
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def expiry_class(expires_at_iso: str | None) -> str:
    """
    Clasifica un cert por su urgencia de expiracion:
      'expired' (ya vencio), 'urgent' (<7d), 'warning' (<15d),
      'notice' (<30d), 'ok' (>=30d), 'unknown' (sin fecha).
    """
    days = days_until(expires_at_iso)
    if days is None:
        return "unknown"
    if days < 0:
        return "expired"
    if days < EXPIRY_THRESHOLDS_DAYS["urgent"]:
        return "urgent"
    if days < EXPIRY_THRESHOLDS_DAYS["warning"]:
        return "warning"
    if days < EXPIRY_THRESHOLDS_DAYS["notice"]:
        return "notice"
    return "ok"


def get_active_emission(user_id: int) -> dict | None:
    """Devuelve la emision activa mas reciente del usuario, o None."""
    init_db()
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT * FROM cert_emissions
            WHERE user_id = ? AND status = 'active'
            ORDER BY issued_at DESC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_emissions_with_status() -> list[dict]:
    """
    Devuelve TODAS las emisiones con metadatos de usuario y clase de expiracion.
    Ordenado por urgencia (las que vencen pronto primero).
    """
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT e.id, e.issued_at, e.issued_ip, e.filename,
                   e.expires_at, e.serial, e.status, e.superseded_by,
                   u.email, u.nombre
            FROM cert_emissions e
            JOIN usuarios u ON u.id = e.user_id
            ORDER BY (e.expires_at IS NULL), e.expires_at ASC
            """
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["expiry_class"] = expiry_class(d.get("expires_at"))
            d["days_remaining"] = days_until(d.get("expires_at"))
            result.append(d)
        return result
    finally:
        conn.close()


def expiry_summary() -> dict:
    """Conteos por clase de expiracion sobre las emisiones con status='active'."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT expires_at FROM cert_emissions WHERE status = 'active'"
        ).fetchall()
    finally:
        conn.close()

    summary = {"ok": 0, "notice": 0, "warning": 0, "urgent": 0, "expired": 0, "unknown": 0}
    for r in rows:
        summary[expiry_class(r["expires_at"])] += 1
    summary["total_active"] = sum(summary.values())
    return summary


# ──────────────────────────────────────────────────────────
#  Validacion automatica de cadenas (Punto 16-17)
# ──────────────────────────────────────────────────────────
def update_validation_status(emission_id: int, status: str):
    """Marca el resultado de la ultima validacion de una emision."""
    init_db()
    conn = _connect()
    try:
        conn.execute(
            """
            UPDATE cert_emissions
            SET validation_status = ?, validation_at = ?
            WHERE id = ?
            """,
            (status, datetime.utcnow().isoformat() + "Z", emission_id),
        )
        conn.commit()
    finally:
        conn.close()


def count_validation_failures() -> dict:
    """Cuenta emisiones activas por estado de validacion."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT validation_status, COUNT(*) as n
            FROM cert_emissions
            WHERE status = 'active'
            GROUP BY validation_status
            """
        ).fetchall()
    finally:
        conn.close()

    summary = {"pass": 0, "warning": 0, "fail": 0, "unchecked": 0}
    for r in rows:
        key = r["validation_status"] or "unchecked"
        summary[key] = summary.get(key, 0) + r["n"]
    summary["total_active"] = sum(summary.values())
    return summary

# ──────────────────────────────────────────────────────────
#  Funciones a llamar para las auditorias y Logs (Puntos 55 ~ 60)
# ──────────────────────────────────────────────────────────
def registrar_evento(evento: str, usuario_id: int = None, detalles: str = None, ip: str = None):
    init_db()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO audit_logs (fecha, evento, usuario_id, detalles, ip_origen) VALUES (?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat() + "Z", evento, usuario_id, detalles, ip)
        )
        conn.commit()
    finally:
        conn.close()

# Función que revisará periodicamente el estado, se puede llamar desde el panel del Admin para generar un reporte de "salud" de los certs.
def auditoria_revocacion():
    """Revisa si hay discrepancias entre los certs activos y la base de datos."""
    emisiones = list_emissions_with_status()
    total = len(emisiones)
    revocados = sum(1 for e in emisiones if e['status'] == 'revoked')
    
    reporte = f"Auditoría completada: {total} certificados analizados. {revocados} revocados."
    registrar_evento("AUDITORIA_REVOCACION", detalles=reporte)
    return reporte