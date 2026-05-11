"""
PKI Académica S/MIME — Paso 3: Certificados PKCS#12 de Usuarios Finales
Genera: <usuario>.p12 para cada usuario definido en la lista
Utiliza: inter-ca.key, inter-ca.crt, chain.crt (del Paso 2)
Uso: python paso3_usuarios_p12.py
"""

import subprocess
import sys
from pathlib import Path
from getpass import getpass

from crypto_core.config import CRL_URL


# ──────────────────────────────────────────────────────────
#  Lista de usuarios finales
# ──────────────────────────────────────────────────────────
USUARIOS = [
    {
        "nombre":   "Jaime",
        "email":    "jaime.chumacero@anahuac.mx",
        "filename": "jaime_chuma",       # Nombre base para los archivos
    },
]

# ──────────────────────────────────────────────────────────
#  Configuración general
# ──────────────────────────────────────────────────────────
USER_CONFIG = {
    "country":      "MX",
    "state":        "Estado de Mexico",
    "locality":     "Huixquilucan",
    "org":          "Universidad Anahuac",
    "org_unit":     "Alumnos",
    "valid_days":   365,       # 1 año
    "key_size":     2048,      # Suficiente para entidad final
}

OUTPUT_DIR    = Path("usuarios_p12_output")
DIR_INTER     = Path("ca_intermedia_output")

# Rutas de ENTRADA (del Paso 2)
inter_crt_path = DIR_INTER / "inter-ca.crt"
inter_key_path = DIR_INTER / "inter-ca.key"
chain_crt_path = DIR_INTER / "chain.crt"

# ──────────────────────────────────────────────────────────
#  Funciones
# ──────────────────────────────────────────────────────────
def run(cmd):
    """Ejecuta un comando del sistema y aborta si falla."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\n[ERROR] Comando falló: {' '.join(cmd)}")
        raise RuntimeError(f"OpenSSL Error:\n{result.stderr}")
    return result

def build_subject(nombre, email):
    """Construye el subject (DN) del certificado del usuario."""
    c  = USER_CONFIG["country"]
    st = USER_CONFIG["state"]
    l  = USER_CONFIG["locality"]
    o  = USER_CONFIG["org"]
    ou = USER_CONFIG["org_unit"]
    return f"/C={c}/ST={st}/L={l}/O={o}/OU={ou}/CN={nombre}"

def get_user_password(nombre):
    """Solicita y confirma la contraseña del archivo .p12 del usuario (Modo Terminal)."""
    while True:
        password = getpass(f"    Contraseña para el .p12 de {nombre}: ")
        confirm  = getpass(f"    Confirma la contraseña: ")
        if len(password) < 8:
            print("    [!] Mínimo 8 caracteres.")
        elif password != confirm:
            print("    [!] Las contraseñas no coinciden.")
        else:
            return password

def generate_user_p12(usuario, inter_password=None, p12_password_web=None, master_password=None):
    """
    Genera el archivo PKCS#12 para un usuario individual.

    Flujo:
      1. Generar clave privada RSA del usuario
      2. Generar CSR con sus datos
      3. Firmar el CSR con la CA Intermedia
      4. Empaquetar todo en un .p12
      5. Limpiar archivos temporales
    """
    for path in [inter_crt_path, inter_key_path, chain_crt_path]:
        if not path.exists():
            raise RuntimeError(
                f"No se encontró: {path}\n"
                "Asegúrate de ejecutar los Pasos 1 y 2 primero."
            )

    OUTPUT_DIR.mkdir(exist_ok=True)

    print("=" * 60)
    print("  PKI Académica — Paso 3: Certificados de Usuario (PKCS#12)")
    print("=" * 60)

    # Pedimos la contraseña de la CA Intermedia una sola vez
    if inter_password is None:
        inter_password = getpass("  Contraseña de la CA Intermedia (para firmar): ")
    
    nombre   = usuario["nombre"]
    email    = usuario["email"]
    filename = usuario["filename"]

    print(f"\n  --- Generando certificado para: {nombre} ({email}) ---")

    # Rutas temporales (se eliminan al final)
    user_key_path = OUTPUT_DIR / f"{filename}.key"
    user_csr_path = OUTPUT_DIR / f"{filename}.csr"
    user_crt_path = OUTPUT_DIR / f"{filename}.crt"
    user_ext_path = OUTPUT_DIR / f"{filename}_ext.cnf"

    # Ruta del producto final
    user_p12_path = OUTPUT_DIR / f"{filename}.p12"

    subject = build_subject(nombre, email)

    # ── 1. Generar clave privada del usuario ──
    print(f"    [1/5] Generando clave privada RSA-{USER_CONFIG['key_size']}...")
    run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-pkeyopt", f"rsa_keygen_bits:{USER_CONFIG['key_size']}",
        "-out", str(user_key_path)
    ])

    # ── 2. Generar CSR ──
    print(f"    [2/5] Generando CSR...")
    run([
        "openssl", "req",
        "-new",
        "-key", str(user_key_path),
        "-subj", subject,
        "-out", str(user_csr_path)
    ])

    # ── 3. Firmar con la CA Intermedia ──
    print(f"    [3/5] Firmando certificado con la CA Intermedia...")

    # Archivo de extensiones S/MIME para el usuario
    user_ext_path.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment\n"
        "extendedKeyUsage=emailProtection\n"
        f"subjectAltName=email:{email}\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
        f"crlDistributionPoints=URI:{CRL_URL}\n"
    )

    run([
        "openssl", "x509",
        "-req",
        "-in", str(user_csr_path),
        "-CA", str(inter_crt_path),
        "-CAkey", str(inter_key_path),
        "-passin", f"pass:{inter_password}",
        "-CAcreateserial",
        "-days", str(USER_CONFIG["valid_days"]),
        "-sha256",
        "-extfile", str(user_ext_path),
        "-out", str(user_crt_path)
    ])

    # ── 4. Empaquetar en PKCS#12 ──
    print(f"    [4/5] Empaquetando en PKCS#12...")

    if p12_password_web is None:
        p12_password = get_user_password(nombre)
    else:
        p12_password = p12_password_web

    run([
        "openssl", "pkcs12",
        "-export",
        "-in", str(user_crt_path),         # Certificado del usuario
        "-inkey", str(user_key_path),       # Clave privada del usuario
        "-certfile", str(chain_crt_path),   # Cadena de confianza (Inter + Root)
        "-name", f"S/MIME {nombre}",        # Nombre amigable en el cliente de correo
        "-passout", f"pass:{p12_password}", # Contraseña de protección del .p12
        "-out", str(user_p12_path)
    ])

    # ── 4b. Guardar copia en escrow administrativo (KRA) ──
    if master_password:
        from crypto_core.escrow import store_escrow
        store_escrow(
            filename,
            user_key_path.read_bytes(),
            user_crt_path.read_bytes(),
            master_password,
        )
        print(f"    [+] Cofre de {filename} guardado en escrow para recuperacion.")

    # ── 5. Limpiar archivos temporales ──
    print(f"    [5/5] Limpiando archivos temporales...")
    # Nota: user_crt_path NO se borra — es necesario para revocar el certificado mas adelante.
    for temp_file in [user_key_path, user_csr_path, user_ext_path]:
        temp_file.unlink(missing_ok=True)

    print(f"    ✔ {user_p12_path} generado exitosamente.")


if __name__ == "__main__":
    for usuario in USUARIOS:
        generate_user_p12(usuario)