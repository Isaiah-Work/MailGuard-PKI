"""
PKI Académica S/MIME — Paso 2: Autoridad Certificadora Intermedia
Genera: inter-ca.key, inter-ca.crt, chain.crt
Utiliza: root.crt y root-ca.key (del Paso 1)
Uso: python paso2_inter_ca.py
"""

import subprocess
import sys
from pathlib import Path
from getpass import getpass

CA_CONFIG = {
    "country":      "MX",
    "state":        "Estado de Mexico",
    "locality":     "Huixquilucan",
    "org":          "Universidad Anahuac",
    "org_unit":     "Emisión SMIME",
    "common_name":  "CI Correos Alumnos 2026",
    "email":        "alexander.oliva@anahuac.mx", # Puede ser el mismo
    "valid_days":   1825, # 3650 / 2
    "key_size":     4096,
}

OUTPUT_DIR = Path("ca_intermedia_output")
DIR_ROOT = Path("root_ca_output")

# Definimos claramente las rutas de ENTRADA (del Paso 1)
root_crt_path = DIR_ROOT / "root.crt"
root_key_path = DIR_ROOT / "root-ca.key"

# Funciones útiles
def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\n[ERROR] Comando falló: {' '.join(cmd)}")
        # Levantamos un error de Python nativo en lugar de sys.exit(1)
        raise RuntimeError(f"OpenSSL Error:\n{result.stderr}")
    return result

def build_subject():
    c  = CA_CONFIG["country"]
    st = CA_CONFIG["state"]
    l  = CA_CONFIG["locality"]
    o  = CA_CONFIG["org"]
    ou = CA_CONFIG["org_unit"]
    cn = CA_CONFIG["common_name"]
    em = CA_CONFIG["email"]
    return f"/C={c}/ST={st}/L={l}/O={o}/OU={ou}/CN={cn}/emailAddress={em}"

# Funciones a cambiar
def generate_ca_intermedio(root_password, inter_password):
    OUTPUT_DIR = Path("ca_intermedia_output")
    DIR_ROOT = Path("root_ca_output")

    # Definimos claramente las rutas de ENTRADA (del Paso 1)
    root_crt_path = DIR_ROOT / "root.crt"
    root_key_path = DIR_ROOT / "root-ca.key"
    
    CA_CONFIG = {
        "country":      "MX",
        "state":        "Estado de Mexico",
        "locality":     "Huixquilucan",
        "org":          "Universidad Anahuac",
        "org_unit":     "Emisión SMIME",
        "common_name":  "CI Correos Alumnos 2026",
        "email":        "alexander.oliva@anahuac.mx", # Puede ser el mismo
        "valid_days":   1825, # 3650 / 2
        "key_size":     4096,
    }

     # Validamos que los archivos del Paso 1 existan antes de empezar
    if not root_crt_path.exists() or not root_key_path.exists():
        print(f"\n[ERROR] No se encontraron los archivos de la Root CA en {DIR_ROOT}")
        print("Asegúrate de ejecutar el Paso 1 primero.")
        sys.exit(1)

    OUTPUT_DIR.mkdir(exist_ok=True)

   # Definimos claramente las rutas de SALIDA para este paso
    inter_key_path = OUTPUT_DIR / "inter-ca.key"
    inter_csr_path = OUTPUT_DIR / "inter-ca.csr" # Archivo temporal
    inter_crt_path = OUTPUT_DIR / "inter-ca.crt" # Certificado final
    chain_crt_path = OUTPUT_DIR / "chain.crt"    # Cadena de confianza

    #key_path  = OUTPUT_DIR / "ca-intermedia.key"
    #csr_path  = OUTPUT_DIR / "intermedia-ca.crt"
    # public_path = OUTPUT_DIR / "intermedia.crt"

    print("=" * 60)
    print("  PKI Académica — Paso 2: CA Intermedia")
    print("=" * 60)

    # Pedimos la cotraseña del root para desencriptar y la nueva para firmar al CA intermedio.
    root_password = getpass("  Contraseña de la Root CA (para firmar): ")
    print("\n  -- Credenciales para la NUEVA CA Intermedia --")
    inter_password = get_password()

    subject  = build_subject() # Creamos el Subject de esta nueva CA.

    print(f"\n[1/4] Generando clave privada RSA-{CA_CONFIG['key_size']} para CA Intermedia...")
    run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-pkeyopt", f"rsa_keygen_bits:{CA_CONFIG['key_size']}",
        "-aes-256-cbc",
        "-pass", f"pass:{inter_password}",
        "-out", str(inter_key_path)
    ])
    print(f"      ✔ {inter_key_path}")

    print("[2/4] Generando petición de Firma (CSR) ...")
    run([
        "openssl", "req",
        "-new",
        "-key", str(inter_key_path),
        "-passin", f"pass:{inter_password}",
        "-subj", subject,
        "-out", str(inter_csr_path)
    ])
    print(f"      ✔ {inter_csr_path}")

    print("[3/4] Firmando certificado con la Root CA...")

    ext_file = OUTPUT_DIR / "inter_ext.cnf"
    ext_file.write_text(
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"
        "subjectKeyIdentifier=hash\n"
    )

    run([
        "openssl", "x509",
        "-req",
        "-in", str(inter_csr_path),
        "-CA", str(root_crt_path),
        "-CAkey", str(root_key_path),
        "-passin", f"pass:{root_password}",
        "-CAcreateserial",
        "-days", str(CA_CONFIG["valid_days"]),
        "-sha256",
        "-extfile", str(ext_file),
        "-out", str(inter_crt_path)
    ])

    print("[4/4] Construyendo cadena de confianza y limpiando...")
    # Leemos ambos certificados públicos
    inter_crt_content = inter_crt_path.read_text()
    root_crt_content = root_crt_path.read_text()

    # Los concatenamos (Intermedio primero, Root después)
    chain_crt_path.write_text(inter_crt_content + "\n" + root_crt_content)
    print(f"      ✔ {chain_crt_path} creada.")
    inter_csr_path.unlink(missing_ok=True)
    ext_file.unlink(missing_ok=True)
    print("      ✔ Archivos temporales (CSR y .cnf) eliminados.")

    # --- Resumen Final ---
    print("\n" + "=" * 60)
    print("  ✔ CA Intermedia generada exitosamente")
    print("=" * 60)
    print(f"\n  Archivos en: {OUTPUT_DIR.resolve()}/")
    print(f"    inter-ca.key  — Clave privada de la CA Intermedia (¡PROTEGER!)")
    print(f"    inter-ca.crt  — Certificado público de la CA Intermedia")
    print(f"    chain.crt     — Cadena de confianza completa (Intermedia + Root)\n")


if __name__ == "__main__":
    generate_ca_intermedio()