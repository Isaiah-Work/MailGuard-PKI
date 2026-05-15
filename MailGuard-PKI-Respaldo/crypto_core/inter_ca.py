"""
PKI Académica S/MIME — Paso 2: Autoridad Certificadora Intermedia
Genera: inter-ca.key, inter-ca.crt, chain.crt
Utiliza: root.crt y root-ca.key (del Paso 1)
Uso: python paso2_inter_ca.py
"""

import subprocess
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
def generate_ca_intermedio(root_password=None, inter_password=None, master_password=None):
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
        raise RuntimeError(
            f"No se encontraron los archivos de la Root CA en {DIR_ROOT}.\n"
            "Asegúrate de ejecutar el Paso 1 primero."
        )

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
    if(root_password is None):
        root_password = getpass("  Contraseña de la Root CA (para firmar): ")
    print("\n  -- Credenciales para la NUEVA CA Intermedia --")
    
    if(inter_password is None):
        print("\n  -- Credenciales para la NUEVA CA Intermedia --")
        inter_password = getpass("  Contraseña para la CA Intermedia: ")

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
        "authorityKeyIdentifier=keyid,issuer\n"
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

    # --- Preparar infraestructura para CRL ---
    print("[+] Preparando base de datos para CRL...")
    index_path = OUTPUT_DIR / "index.txt"
    index_path.touch(exist_ok=True)

    crlnumber_path = OUTPUT_DIR / "crlnumber"
    if not crlnumber_path.exists():
        crlnumber_path.write_text("01\n")

    crl_dir = OUTPUT_DIR / "crl"
    crl_dir.mkdir(exist_ok=True)
    print("      ✔ index.txt, crlnumber y directorio crl/ listos.")

    # Generar CRL inicial (vacío) para que el endpoint /crl/inter-ca.crl
    # responda desde el día 1, antes de cualquier revocación.
    from crypto_core.crl import generar_crl
    generar_crl(inter_password)
    print("      ✔ CRL inicial vacío generado.")

    # --- Inicializar escrow administrativo (KRA) ---
    if master_password:
        from crypto_core.escrow import initialize_master
        initialize_master(master_password)
        print("      ✔ Master de escrow (KRA) inicializado.")

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