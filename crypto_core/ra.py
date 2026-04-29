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
from datetime import datetime
from pathlib import Path

from crypto_core.config import ADMIN_PASSWORD, RA_DB_PATH

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
    """Crea las tablas si no existen. Idempotente."""
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
    """)
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


def admin_lock():
    """Olvida los passwords cacheados. Tras esto, /solicitar deja de funcionar."""
    _session.clear()


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
            raise PermissionError("Credenciales invalidas.")

        conn.execute(
            "UPDATE usuarios SET failed_attempts = 0, last_request_at = ? WHERE id = ?",
            (datetime.utcnow().isoformat() + "Z", row["id"]),
        )
        conn.commit()
        return dict(row)
    finally:
        conn.close()


def record_emission(user_id: int, filename: str, ip: str | None = None):
    init_db()
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO cert_emissions (user_id, issued_at, issued_ip, filename)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, datetime.utcnow().isoformat() + "Z", ip, filename),
        )
        conn.commit()
    finally:
        conn.close()
