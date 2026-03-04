import subprocess
import sys
from pathlib import Path
from getpass import getpass

CA_CONFIG = {
    "country":      "MX",
    "state":        "Estado de Mexico",
    "locality":     "Huixquilucan",
    "org":          "Universidad Anahuac",
    "org_unit":     "Matemáticas Discretas",
    "common_name":  "Root CA Anahuac 2026",
    "email":        "alexander.oliva@anahuac.mx",
    "valid_days":   3650,
    "key_size":     4096,
}

OUTPUT_DIR = Path("root_ca_output")

def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\n[ERROR] {result.stderr}")
        sys.exit(1)
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


def generate_root_ca(root_password=None):


    OUTPUT_DIR.mkdir(exist_ok=True)

    key_path  = OUTPUT_DIR / "root-ca.key"
    crt_path  = OUTPUT_DIR / "root-ca.crt"
    root_path = OUTPUT_DIR / "root.crt"

    print("=" * 60)
    print("  PKI Académica — Paso 1: Root CA")
    print("=" * 60)
    print("\n[!] La clave privada se cifrará con AES-256.\n")

    if root_password is None:
        password = getpass()
    else:
        password = root_password

    subject  = build_subject()

    print(f"\n[1/3] Generando clave privada RSA-{CA_CONFIG['key_size']}...")
    
    run([
        "openssl", "genpkey",
        "-algorithm", "RSA",
        "-pkeyopt", f"rsa_keygen_bits:{CA_CONFIG['key_size']}",
        "-aes-256-cbc",
        "-pass", f"pass:{password}",
        "-out", str(key_path)
    ])
    print(f"      ✔ {key_path}")

    print("[2/3] Generando certificado X.509 auto-firmado...")
    run([
        "openssl", "req",
        "-new", "-x509",
        "-key", str(key_path),
        "-passin", f"pass:{password}",
        "-sha256",
        "-days", str(CA_CONFIG["valid_days"]),
        "-subj", subject,
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
        "-addext", "subjectKeyIdentifier=hash",
        "-out", str(crt_path)
    ])
    print(f"      ✔ {crt_path}")

    print("[3/3] Copiando certificado raíz para distribución...")
    root_path.write_bytes(crt_path.read_bytes())
    print(f"      ✔ {root_path}")

    info = run(["openssl", "x509", "-in", str(crt_path), "-noout",
                "-subject", "-dates", "-serial", "-fingerprint"])

    print("\n" + "=" * 60)
    print("  ✔ Root CA generada exitosamente")
    print("=" * 60)
    print(f"\n  Archivos en: {OUTPUT_DIR.resolve()}/")
    print(f"    root-ca.key  — Clave privada RSA-{CA_CONFIG['key_size']} (PKCS#8, AES-256)")
    print(f"    root-ca.crt  — Certificado raíz (offline, para firmar CAs)")
    print(f"    root.crt     — Certificado raíz (distribución pública)")
    print(f"\n  Detalles:\n")
    for line in info.stdout.strip().splitlines():
        print(f"    {line}")
    print("\n  IMPORTANTE:")
    print("    • root-ca.key debe mantenerse OFFLINE y protegido.")
    print("    • Solo usa root-ca.crt para firmar la CA intermedia.")
    print("    • root.crt es el archivo a distribuir a los usuarios.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    generate_root_ca()