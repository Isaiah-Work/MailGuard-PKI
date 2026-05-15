import subprocess
from pathlib import Path

DIR_INTER = Path("ca_intermedia_output")
PORT = 8080

def start_ocsp_server():
    print(f"Iniciando Servidor OCSP en el puerto {PORT}...")

    #El comando usa OpenSSL OCSP como servidor ligero
    # -index lee al BD local, -CA indica quién manda, -rsigner/-rkey firman la respuesta.

    cmd = [
        "openssl", "ocsp",
        "-index", str(DIR_INTER / "index.txt"),
        "-port", str(PORT),
        "-rsigner", str(DIR_INTER / "inter-ca.crt"),
        "-rkey", str(DIR_INTER / "inter-ca.key"),
        "-CA", "root_ca_output/root.crt",
        "-text"
    ]

    try:
        #se lanza en primer plano. Se tiene que cerrar con CTRL + C
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nServidor OCSP detenido correctamente")

        if __name__ == "__main__":
            if not (DIR_INTER / "index.txt").exists():
                print("Error: El archivo index.txt no existe. Genera la CA intermedia primero")
            else:
                start_ocsp_server()