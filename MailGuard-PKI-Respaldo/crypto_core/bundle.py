"""
Generador de bundles ZIP listos para Thunderbird.

Cada bundle contiene:
  - MailGuard-RootCA.crt   -> Root CA para confianza
  - {filename}.p12         -> cofre PKCS#12 personal del usuario
  - INSTRUCCIONES.txt      -> guia paso a paso para Thunderbird

La password del .p12 NO se incluye en el bundle por seguridad: el usuario
la eligio en /solicitar y debe mantenerla aparte. Si la pierde, el flujo
de recuperacion (KRA) genera un cofre nuevo con password fresca.
"""

import io
import zipfile
from pathlib import Path

ROOT_CA_PATH = Path("root_ca_output/root.crt")
P12_DIR = Path("usuarios_p12_output")


def build_thunderbird_bundle(filename: str) -> bytes:
    """Construye el ZIP en memoria. Levanta FileNotFoundError si falta material."""
    if not ROOT_CA_PATH.exists():
        raise FileNotFoundError(
            "Root CA no disponible. Ejecuta el Paso 1 primero."
        )
    p12_path = P12_DIR / f"{filename}.p12"
    if not p12_path.exists():
        raise FileNotFoundError(
            f"No existe .p12 para '{filename}'. Solicita uno en /solicitar."
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("MailGuard-RootCA.crt", ROOT_CA_PATH.read_bytes())
        z.writestr(f"{filename}.p12", p12_path.read_bytes())
        z.writestr(
            "INSTRUCCIONES.txt",
            _build_instrucciones(filename).encode("utf-8"),
        )
    return buf.getvalue()


def _build_instrucciones(filename: str) -> str:
    return f"""================================================================
  MailGuard PKI - Instalacion en Thunderbird
================================================================

Tu identidad S/MIME consta de:

  1. MailGuard-RootCA.crt   - certificado raiz de Universidad Anahuac
  2. {filename}.p12         - tu cofre PKCS#12 personal

Sigue estos 4 pasos en orden. Tiempo total: ~3 minutos.

================================================================
  PASO 1: IMPORTAR LA ROOT CA EN THUNDERBIRD
================================================================

Thunderbird tiene su propio almacen de certificados, separado del SO.
La Root CA debe importarse aqui aunque ya este en Windows/macOS.

1. Abre Thunderbird.
2. Menu hamburguesa (esquina superior derecha) > Settings.
3. Barra lateral > Privacy & Security.
4. Scroll hasta la seccion "Certificates".
5. Click en "Manage Certificates...".
6. Pestana "Authorities".
7. Boton "Import..." > selecciona MailGuard-RootCA.crt.
8. En la ventana de confianza, marca:
       [x] Trust this CA to identify email users
9. Click "OK".

================================================================
  PASO 2: IMPORTAR TU CERTIFICADO PERSONAL (.p12)
================================================================

1. Misma ventana "Manage Certificates" (si la cerraste, vuelve a abrirla).
2. Pestana "Your Certificates".
3. Boton "Import..." > selecciona {filename}.p12.
4. Ingresa la contrasena del .p12 que elegiste cuando lo solicitaste.
5. Click "OK".

(Si olvidaste la contrasena: el admin puede emitir un cofre nuevo
 con contrasena fresca usando el modulo KRA. Tu certificado actual
 queda intacto, solo cambia la password de proteccion.)

================================================================
  PASO 3: VINCULAR EL CERTIFICADO A TU CUENTA DE CORREO
================================================================

Thunderbird NO vincula automaticamente el certificado a tu cuenta.

1. Menu hamburguesa > Account Settings.
2. Barra lateral > selecciona tu cuenta @anahuac.mx.
3. Submenu "End-To-End Encryption".
4. Seccion S/MIME:

     Personal certificate for digital signing:
        [Select...] > elige tu certificado.

     Personal certificate for encryption:
        [Select...] > elige el MISMO certificado.

5. Marca:
     [x] Sign messages by default

================================================================
  PASO 4: ENVIAR UN CORREO FIRMADO
================================================================

1. Compose (boton de nuevo correo).
2. Escribe el correo.
3. En la barra superior, antes de enviar:
       icono "Security" (candado) > marca [x] Digitally Sign This Message
   (Si activaste "Sign by default" en el Paso 3, ya estara marcado.)
4. Send.

El destinatario vera un sello indicando que la firma es valida y que
el correo proviene realmente de tu identidad academica.

================================================================
  RESOLUCION DE PROBLEMAS COMUNES
================================================================

* "El certificado no es de confianza"
    -> No importaste la Root CA en Thunderbird (Paso 1) o no marcaste
       "Trust this CA to identify email users".

* "No se ha configurado certificado para firmar"
    -> No vinculaste el cert a la cuenta de correo (Paso 3).

* "Failed to decrypt: la cadena de confianza no se puede establecer"
    -> El destinatario no tiene la Root CA instalada en su Thunderbird.
       Pidele que tambien siga el Paso 1 con MailGuard-RootCA.crt.

* "Olvide la contrasena del .p12"
    -> Contacta al admin. El sistema KRA puede generarte un cofre nuevo
       sin necesidad de re-emitir el certificado.

================================================================
"""
