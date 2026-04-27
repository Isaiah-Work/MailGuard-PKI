"""
Key Recovery Agent (KRA) -- escrow administrativo de cofres .p12.

Permite recuperar el material criptografico (clave + certificado) de un usuario
re-empaquetandolo en un .p12 nuevo con una contrasena fresca, en caso de que
el usuario pierda su .p12 original o su contrasena.

Modelo de seguridad:
- El admin establece un MASTER PASSWORD distinto al de la Inter CA.
- Cada .p12 emitido se duplica como un envelope cifrado con AES-256-CBC bajo
  ese master, conteniendo la clave privada y el cert del usuario.
- La recuperacion verifica el master y produce un .p12 fresco con un nuevo
  password elegido por el admin (que entrega al usuario por canal seguro).
- Cada recuperacion queda registrada en un audit log append-only.

Trade-off: mantener escrow significa que el admin puede leer correos cifrados
del usuario, lo que reduce la garantia de no-repudio. Documentar a los usuarios.
"""

import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

DIR_INTER = Path("ca_intermedia_output")
ESCROW_DIR = DIR_INTER / "escrow"
MASTER_CHECK = ESCROW_DIR / "master_check.bin"
AUDIT_LOG = ESCROW_DIR / "audit.log"
SENTINEL = b"MailGuardKRA-OK\n"


def _run(cmd, stdin=None):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode())
    return r.stdout


def _encrypt(data: bytes, password: str) -> bytes:
    return _run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
         "-pass", f"pass:{password}"],
        stdin=data,
    )


def _decrypt(data: bytes, password: str) -> bytes:
    return _run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000", "-d",
         "-pass", f"pass:{password}"],
        stdin=data,
    )


def initialize_master(master_password: str):
    """Establece el master de escrow. Idempotente: si ya existe, valida que coincida."""
    ESCROW_DIR.mkdir(parents=True, exist_ok=True)
    if MASTER_CHECK.exists():
        if not verify_master(master_password):
            raise RuntimeError(
                "El master de escrow ya estaba inicializado pero el password no coincide."
            )
        return
    MASTER_CHECK.write_bytes(_encrypt(SENTINEL, master_password))


def verify_master(master_password: str) -> bool:
    """True si el master ingresado descifra el sentinel correctamente."""
    if not MASTER_CHECK.exists():
        return False
    try:
        return _decrypt(MASTER_CHECK.read_bytes(), master_password) == SENTINEL
    except RuntimeError:
        return False


def store_escrow(filename: str, key_pem: bytes, cert_pem: bytes, master_password: str):
    """Guarda key+cert del usuario en un envelope cifrado con master."""
    if not MASTER_CHECK.exists():
        initialize_master(master_password)
    elif not verify_master(master_password):
        raise RuntimeError("Master password de escrow incorrecto.")
    payload = key_pem.rstrip() + b"\n" + cert_pem.rstrip() + b"\n"
    out = ESCROW_DIR / f"{filename}.escrow.enc"
    out.write_bytes(_encrypt(payload, master_password))


def recover_with_new_password(
    filename: str, master_password: str, new_p12_password: str
) -> bytes:
    """
    Recupera el .p12 de un usuario con un password fresco.

    Flujo:
      1. Verifica el master.
      2. Descifra el envelope, obtiene key + cert PEM.
      3. Reempaqueta como .p12 con el nuevo password.
      4. Registra en audit.log.
      5. Devuelve los bytes del .p12.
    """
    if not verify_master(master_password):
        raise RuntimeError("Master password de escrow incorrecto.")

    enc_path = ESCROW_DIR / f"{filename}.escrow.enc"
    if not enc_path.exists():
        raise FileNotFoundError(f"No hay escrow registrado para {filename}.")

    payload = _decrypt(enc_path.read_bytes(), master_password)

    chain_path = DIR_INTER / "chain.crt"
    if not chain_path.exists():
        raise RuntimeError("chain.crt no encontrado; la Inter CA no esta disponible.")

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        bundle_path = tmp / "bundle.pem"
        bundle_path.write_bytes(payload)
        out_p12 = tmp / "recovered.p12"

        _run([
            "openssl", "pkcs12",
            "-export",
            "-in", str(bundle_path),
            "-inkey", str(bundle_path),
            "-certfile", str(chain_path),
            "-name", f"S/MIME {filename} (recuperado)",
            "-passout", f"pass:{new_p12_password}",
            "-out", str(out_p12),
        ])

        p12_bytes = out_p12.read_bytes()

    _audit(filename)
    return p12_bytes


def _audit(filename: str):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{datetime.utcnow().isoformat()}Z\trecover\t{filename}\n")


def read_audit_log() -> str:
    if not AUDIT_LOG.exists():
        return "(sin recuperaciones registradas)"
    return AUDIT_LOG.read_text(encoding="utf-8")
