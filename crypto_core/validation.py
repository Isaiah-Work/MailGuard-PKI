"""
Validacion automatica de cadenas X.509 y distribucion de intermedios.

Cubre los 14 checks:
  Punto 16 (validacion de cadena): 1-10
  Punto 50 (distribucion de intermedios): 11-14

Cada check devuelve un dict con:
  - id: numero del check
  - name: descripcion legible
  - level: 'critical' | 'warning' | 'info'
  - passed: True | False | None (None = saltado)
  - detail: explicacion textual del resultado

Niveles:
  - critical: si falla, el cert no funciona en clientes de correo.
  - warning:  funciona pero hay riesgo (vence pronto, algoritmo legacy).
  - info:     informativo, no afecta funcionamiento.
"""

import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Rutas estandar de los archivos de la PKI
ROOT_CA_CRT = Path("root_ca_output/root.crt")
INTER_CA_CRT = Path("ca_intermedia_output/inter-ca.crt")
CHAIN_CRT = Path("ca_intermedia_output/chain.crt")
CRL_PATH = Path("ca_intermedia_output/crl/inter-ca.crl")
USERS_DIR = Path("usuarios_p12_output")


# ──────────────────────────────────────────────────────────
#  API publica
# ──────────────────────────────────────────────────────────
def validate_user_cert(filename: str, p12_password: str | None = None) -> dict:
    """
    Ejecuta los 14 checks sobre el cert <filename>.crt y su .p12.

    Si p12_password se provee, se incluye el check 12 (PKCS#12 contiene cadena).
    Sin password, ese check se marca como 'saltado'.
    """
    user_crt = USERS_DIR / f"{filename}.crt"
    user_p12 = USERS_DIR / f"{filename}.p12"

    if not user_crt.exists():
        return {
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall": "fail",
            "checks": [{
                "id": 0,
                "name": "Cert de usuario existe en disco",
                "level": "critical",
                "passed": False,
                "detail": f"No existe {user_crt}",
            }],
        }

    checks = []

    # ── Checks de cadena (Punto 16) ──
    checks.append(_check_chain_verify(user_crt, CHAIN_CRT))
    checks.append(_check_dates(user_crt, "Cert de usuario", check_id=2))
    checks.append(_check_dates_warning(user_crt, "Cert de usuario", days=30, check_id=3))
    checks.append(_check_dates(INTER_CA_CRT, "Inter CA", check_id=4))
    checks.append(_check_dn_match(user_crt, INTER_CA_CRT,
                                   "user.Issuer == inter.Subject", check_id=5))
    checks.append(_check_dn_match(INTER_CA_CRT, ROOT_CA_CRT,
                                   "inter.Issuer == root.Subject", check_id=6))
    checks.append(_check_aki_ski(user_crt, INTER_CA_CRT,
                                  "user.AKI == inter.SKI", check_id=7))
    checks.append(_check_aki_ski(INTER_CA_CRT, ROOT_CA_CRT,
                                  "inter.AKI == root.SKI", check_id=8))
    checks.append(_check_root_self_signed(ROOT_CA_CRT))
    checks.append(_check_algorithms_strong([user_crt, INTER_CA_CRT, ROOT_CA_CRT]))

    # ── Checks de distribucion de intermedios (Punto 50) ──
    checks.append(_check_chain_crt_exists())
    checks.append(_check_chain_crt_structure())
    checks.append(_check_p12_chain(user_p12, p12_password))
    checks.append(_check_crl_existence_and_currency())
    checks.append(_check_crl_signed_correctly())

    return _aggregate(filename, checks)


def revalidate_all_active() -> list[dict]:
    """Re-valida todas las emisiones con status='active' y devuelve sus reportes."""
    from crypto_core import ra
    emissions = ra.list_emissions_with_status()
    reports = []
    for e in emissions:
        if e["status"] != "active":
            continue
        report = validate_user_cert(e["filename"])
        report["emission_id"] = e["id"]
        report["email"] = e["email"]
        ra.update_validation_status(e["id"], report["overall"])
        reports.append(report)
    return reports


# ──────────────────────────────────────────────────────────
#  Helpers de parseo
# ──────────────────────────────────────────────────────────
def _run_x509(cert_path: Path, *flags: str) -> str:
    return subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", *flags],
        capture_output=True, text=True
    ).stdout


def _parse_subject_issuer(cert_path: Path) -> dict:
    out = _run_x509(cert_path, "-subject", "-issuer")
    subject, issuer = "", ""
    for line in out.splitlines():
        if line.startswith("subject="):
            subject = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer="):].strip()
    return {"subject": subject, "issuer": issuer}


def _parse_keyid(cert_path: Path, ext_name: str) -> str:
    """Extrae el keyid hex (sin colons, lowercase) de AKI o SKI."""
    out = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path),
         "-noout", "-ext", ext_name],
        capture_output=True, text=True
    ).stdout
    hex_part = ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("keyid:"):
            hex_part = s[len("keyid:"):]
            break
        if re.match(r"^[0-9A-Fa-f:]{20,}$", s):
            hex_part = s
            break
    return hex_part.replace(":", "").lower()


# ──────────────────────────────────────────────────────────
#  Checks individuales
# ──────────────────────────────────────────────────────────
def _check_chain_verify(user_crt: Path, chain: Path) -> dict:
    if not chain.exists():
        return _fail(1, "Cadena valida (openssl verify)", "critical",
                     f"chain.crt no existe en {chain}")
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(chain), str(user_crt)],
        capture_output=True, text=True
    )
    passed = result.returncode == 0 and "OK" in result.stdout
    return {
        "id": 1,
        "name": "Cadena valida (openssl verify)",
        "level": "critical",
        "passed": passed,
        "detail": result.stdout.strip() if passed else (result.stderr.strip()[:300] or result.stdout.strip()),
    }


def _check_dates(cert_path: Path, label: str, check_id: int) -> dict:
    if not cert_path.exists():
        return _fail(check_id, f"{label} no expirado", "critical",
                     f"{cert_path} no existe")
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "0"],
        capture_output=True, text=True
    )
    valid = result.returncode == 0
    enddate_out = _run_x509(cert_path, "-enddate")
    enddate = enddate_out.split("=", 1)[1].strip() if "=" in enddate_out else "?"
    return {
        "id": check_id,
        "name": f"{label} no expirado",
        "level": "critical",
        "passed": valid,
        "detail": f"notAfter = {enddate}",
    }


def _check_dates_warning(cert_path: Path, label: str, days: int, check_id: int) -> dict:
    seconds = days * 24 * 3600
    result = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", str(seconds)],
        capture_output=True, text=True
    )
    valid_window = result.returncode == 0
    return {
        "id": check_id,
        "name": f"{label} vigente al menos {days} dias mas",
        "level": "warning",
        "passed": valid_window,
        "detail": "OK" if valid_window else f"Vence dentro de {days} dias",
    }


def _check_dn_match(child_cert: Path, parent_cert: Path, name: str, check_id: int) -> dict:
    if not child_cert.exists() or not parent_cert.exists():
        return _fail(check_id, name, "critical", "Cert de cadena ausente")
    child = _parse_subject_issuer(child_cert)
    parent = _parse_subject_issuer(parent_cert)
    passed = child["issuer"] == parent["subject"] and child["issuer"] != ""
    return {
        "id": check_id,
        "name": name,
        "level": "critical",
        "passed": passed,
        "detail": (
            f"child.Issuer  = {child['issuer']}\n"
            f"parent.Subject = {parent['subject']}"
        ),
    }


def _check_aki_ski(child_cert: Path, parent_cert: Path, name: str, check_id: int) -> dict:
    if not child_cert.exists() or not parent_cert.exists():
        return _fail(check_id, name, "critical", "Cert de cadena ausente")
    child_aki = _parse_keyid(child_cert, "authorityKeyIdentifier")
    parent_ski = _parse_keyid(parent_cert, "subjectKeyIdentifier")
    passed = bool(child_aki) and child_aki == parent_ski
    return {
        "id": check_id,
        "name": name,
        "level": "critical",
        "passed": passed,
        "detail": (
            f"child.AKI  = {child_aki[:32]}{'...' if len(child_aki)>32 else ''}\n"
            f"parent.SKI = {parent_ski[:32]}{'...' if len(parent_ski)>32 else ''}"
        ),
    }


def _check_root_self_signed(root_cert: Path) -> dict:
    if not root_cert.exists():
        return _fail(9, "Root CA es self-signed", "critical", "root.crt no existe")
    info = _parse_subject_issuer(root_cert)
    passed = info["subject"] == info["issuer"] and info["subject"] != ""
    # Tambien validar criptograficamente
    result = subprocess.run(
        ["openssl", "verify", "-CAfile", str(root_cert), str(root_cert)],
        capture_output=True, text=True
    )
    crypto_ok = "OK" in result.stdout
    return {
        "id": 9,
        "name": "Root CA es self-signed (DN matching + firma valida)",
        "level": "critical",
        "passed": passed and crypto_ok,
        "detail": f"DN match: {passed}, openssl verify: {result.stdout.strip()}",
    }


def _check_algorithms_strong(certs: list[Path]) -> dict:
    weak = []
    for c in certs:
        if not c.exists():
            continue
        text = _run_x509(c, "-text")
        # Buscar primer Signature Algorithm
        for line in text.splitlines():
            if "Signature Algorithm" in line:
                algo = line.split(":", 1)[1].strip().lower()
                if "sha1" in algo or "md5" in algo or "md2" in algo:
                    weak.append(f"{c.name}: {algo}")
                break
        # Buscar tamano de llave RSA
        for line in text.splitlines():
            m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", line)
            if m:
                bits = int(m.group(1))
                if bits < 2048:
                    weak.append(f"{c.name}: RSA-{bits}")
                break
    passed = len(weak) == 0
    return {
        "id": 10,
        "name": "Algoritmos fuertes (>=SHA-256, >=RSA-2048)",
        "level": "critical",
        "passed": passed,
        "detail": "Todos los algoritmos OK" if passed else f"Debiles: {weak}",
    }


def _check_chain_crt_exists() -> dict:
    return {
        "id": 11,
        "name": "chain.crt existe",
        "level": "critical",
        "passed": CHAIN_CRT.exists(),
        "detail": str(CHAIN_CRT) if CHAIN_CRT.exists() else f"No existe {CHAIN_CRT}",
    }


def _check_chain_crt_structure() -> dict:
    """Verifica que chain.crt tenga 2 certs en orden Inter -> Root."""
    if not CHAIN_CRT.exists():
        return _fail(12, "chain.crt orden correcto (Inter primero, Root ultimo)",
                     "critical", "chain.crt no existe")

    content = CHAIN_CRT.read_text()
    # Particionar en bloques BEGIN/END CERTIFICATE
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        content, flags=re.DOTALL
    )
    if len(blocks) != 2:
        return {
            "id": 12,
            "name": "chain.crt contiene 2 certs en orden correcto",
            "level": "critical",
            "passed": False,
            "detail": f"Encontrados {len(blocks)} certs (esperados 2: Inter + Root)",
        }

    # Escribir cada bloque a tmp y obtener subject
    def get_subject(pem_block: str) -> str:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tmp:
            tmp.write(pem_block + "\n")
            tmp_path = Path(tmp.name)
        try:
            return _parse_subject_issuer(tmp_path)["subject"]
        finally:
            tmp_path.unlink(missing_ok=True)

    first_subject = get_subject(blocks[0])
    last_subject = get_subject(blocks[1])

    expected_inter = _parse_subject_issuer(INTER_CA_CRT)["subject"] if INTER_CA_CRT.exists() else ""
    expected_root = _parse_subject_issuer(ROOT_CA_CRT)["subject"] if ROOT_CA_CRT.exists() else ""

    correct = first_subject == expected_inter and last_subject == expected_root
    return {
        "id": 12,
        "name": "chain.crt orden correcto (Inter primero, Root ultimo)",
        "level": "critical",
        "passed": correct,
        "detail": (
            f"first.Subject = {first_subject[:60]}{'...' if len(first_subject)>60 else ''}\n"
            f"last.Subject  = {last_subject[:60]}{'...' if len(last_subject)>60 else ''}"
        ),
    }


def _check_p12_chain(p12_path: Path, password: str | None) -> dict:
    if not p12_path.exists():
        return _fail(13, "PKCS#12 lleva cadena completa", "critical",
                     f"{p12_path} no existe")
    if password is None:
        return {
            "id": 13,
            "name": "PKCS#12 lleva cadena completa (user + inter + root)",
            "level": "info",
            "passed": None,
            "detail": "Saltado: password del .p12 no provista al validador",
        }
    result = subprocess.run(
        ["openssl", "pkcs12", "-in", str(p12_path),
         "-nokeys", "-passin", f"pass:{password}"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return {
            "id": 13,
            "name": "PKCS#12 lleva cadena completa",
            "level": "critical",
            "passed": False,
            "detail": f"No se pudo leer .p12: {result.stderr.strip()[:200]}",
        }
    count = result.stdout.count("BEGIN CERTIFICATE")
    return {
        "id": 13,
        "name": "PKCS#12 lleva cadena completa (3 certs: user + inter + root)",
        "level": "critical",
        "passed": count >= 3,
        "detail": f"Encontrados {count} certs en el .p12 (esperados 3)",
    }


def _check_crl_existence_and_currency() -> dict:
    if not CRL_PATH.exists():
        return _fail(14, "CRL existe y vigente", "critical",
                     f"No existe {CRL_PATH}. Ejecuta el Paso 2 o regenera CRL.")

    # nextUpdate > now
    out = subprocess.run(
        ["openssl", "crl", "-in", str(CRL_PATH), "-noout", "-nextupdate"],
        capture_output=True, text=True
    ).stdout
    if "=" not in out:
        return _fail(14, "CRL vigente", "critical", "No se pudo leer nextUpdate")
    raw = out.split("=", 1)[1].strip()  # "May 29 14:00:00 2026 GMT"
    no_tz = raw.rsplit(" ", 1)[0]
    next_update = datetime.strptime(no_tz, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
    expired = next_update < datetime.now(timezone.utc)

    return {
        "id": 14,
        "name": "CRL vigente (nextUpdate en el futuro)",
        "level": "warning" if expired else "info",
        "passed": not expired,
        "detail": f"nextUpdate = {raw}" + (" (EXPIRADO)" if expired else ""),
    }


def _check_crl_signed_correctly() -> dict:
    if not CRL_PATH.exists() or not INTER_CA_CRT.exists():
        return _fail(15, "CRL firmado por Inter CA", "critical",
                     "Falta CRL o inter-ca.crt")

    issuer_out = subprocess.run(
        ["openssl", "crl", "-in", str(CRL_PATH), "-noout", "-issuer"],
        capture_output=True, text=True
    ).stdout
    crl_issuer = issuer_out.split("=", 1)[1].strip() if "=" in issuer_out else ""
    inter_subject = _parse_subject_issuer(INTER_CA_CRT)["subject"]
    issuer_matches = crl_issuer == inter_subject and crl_issuer != ""

    # Tambien validar la firma criptograficamente
    verify = subprocess.run(
        ["openssl", "crl", "-in", str(CRL_PATH),
         "-CAfile", str(CHAIN_CRT), "-noout"],
        capture_output=True, text=True
    )
    crypto_ok = verify.returncode == 0 and not verify.stderr.strip()

    return {
        "id": 15,
        "name": "CRL firmado por Inter CA (issuer match + firma valida)",
        "level": "critical",
        "passed": issuer_matches and crypto_ok,
        "detail": (
            f"CRL.issuer    = {crl_issuer[:60]}\n"
            f"Inter.Subject = {inter_subject[:60]}\n"
            f"Verificacion criptografica: {'OK' if crypto_ok else verify.stderr.strip()[:120]}"
        ),
    }


# ──────────────────────────────────────────────────────────
#  Helpers de agregacion
# ──────────────────────────────────────────────────────────
def _fail(check_id: int, name: str, level: str, detail: str) -> dict:
    return {
        "id": check_id,
        "name": name,
        "level": level,
        "passed": False,
        "detail": detail,
    }


def _aggregate(filename: str, checks: list[dict]) -> dict:
    failed_critical = [c for c in checks if c["passed"] is False and c["level"] == "critical"]
    failed_warning = [c for c in checks if c["passed"] is False and c["level"] == "warning"]

    if failed_critical:
        overall = "fail"
    elif failed_warning:
        overall = "warning"
    else:
        overall = "pass"

    return {
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall": overall,
        "checks": checks,
        "summary": {
            "total": len(checks),
            "passed": sum(1 for c in checks if c["passed"] is True),
            "failed_critical": len(failed_critical),
            "failed_warning": len(failed_warning),
            "skipped": sum(1 for c in checks if c["passed"] is None),
        },
    }
