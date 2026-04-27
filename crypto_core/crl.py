"""
PKI Academica S/MIME -- Gestion de CRL (Certificate Revocation List)
Permite revocar certificados de usuario y generar/regenerar el archivo CRL
firmado por la CA Intermedia.
"""

import subprocess
from pathlib import Path

DIR_INTER = Path("ca_intermedia_output")
CNF_PATH = Path("crypto_core/openssl_ca.cnf")


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL Error:\n{result.stderr}")
    return result


def revocar_certificado(cert_path: str, inter_password: str):
    """
    Marca un certificado como revocado en la base de datos de la CA
    y regenera el CRL para que la revocacion sea visible inmediatamente
    a los clientes que consulten el endpoint publico.
    """
    run([
        "openssl", "ca",
        "-config", str(CNF_PATH),
        "-revoke", cert_path,
        "-keyfile", str(DIR_INTER / "inter-ca.key"),
        "-cert", str(DIR_INTER / "inter-ca.crt"),
        "-passin", f"pass:{inter_password}",
    ])
    generar_crl(inter_password)


def generar_crl(inter_password: str):
    """
    Genera (o regenera) el archivo CRL firmado por la CA Intermedia.
    Los clientes de correo consultan este archivo para verificar
    si un certificado ha sido revocado.
    """
    crl_dir = DIR_INTER / "crl"
    crl_dir.mkdir(exist_ok=True)
    crl_path = crl_dir / "inter-ca.crl"

    run([
        "openssl", "ca",
        "-config", str(CNF_PATH),
        "-gencrl",
        "-keyfile", str(DIR_INTER / "inter-ca.key"),
        "-cert", str(DIR_INTER / "inter-ca.crt"),
        "-passin", f"pass:{inter_password}",
        "-out", str(crl_path),
    ])
    return crl_path
