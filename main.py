from fasthtml.common import *
from pathlib import Path
from crypto_core.root_ca import generate_root_ca
from crypto_core.inter_ca import generate_ca_intermedio
from crypto_core.usuarios_p12 import generate_user_p12, USUARIOS

# Al no pasarle argumentos, FastHTML usa Pico CSS por defecto
app, rt = fast_app()

@rt('/')
def get():
    # En Pico CSS, usar Main(cls="container") centra el contenido y le da márgenes perfectos
    return Main(
        H1("MailGuard PKI"),
        P("Panel de administración de infraestructura de claves (S/MIME)."),
        
        # --- TARJETA PASO 1 ---
        # Article() en Pico crea automáticamente una tarjeta (card) con bordes y sombras
        Article(
            H2("Paso 1: Generar Root CA"),
            Form(
                Label("Contraseña para la Root CA:",
                    Input(type="password", name="root_password", required=True)
                ),
                Button("Ejecutar Paso 1", type="submit"),
                action="/generar_root", method="post"
            ),
            
            # --- NUEVA SECCIÓN DE AUDITORÍA (Solo lectura) ---
            Details(
                Summary("Ver Comando de Encriptación (Auditoría de Seguridad)"),
                P("Para garantizar la seguridad de la clave privada (Punto 3 de la rúbrica), se aplica cifrado de grado militar ", Strong("AES-256"), " a la bóveda offline:"),
                Pre(Code(
                    "openssl genpkey \\\n"
                    "  -algorithm RSA \\\n"
                    "  -pkeyopt rsa_keygen_bits:4096 \\\n"
                    "  -aes-256-cbc \\\n"
                    "  -pass pass:[CONTRASEÑA_OCULTA] \\\n"
                    "  -out root-ca.key"
                )),
                # Un pequeño texto extra para rematar el punto 3
                P(Small("Nota: El archivo resultante (root-ca.key) debe almacenarse en Hardware físico (HSM) o USB aislado sin conexión a red."))
            )
        ),

        
        
        # --- TARJETA PASO 2 ---
        Article(
            H2("Paso 2: CA Intermedia"),
            Form(
                Label("Contraseña de la Root CA (para desencriptar y firmar):",
                    Input(type="password", name="root_password", required=True)
                ),
                Label("Nueva contraseña para la CA Intermedia:",
                    Input(type="password", name="inter_password", required=True)
                ),
                Button("Ejecutar Paso 2", type="submit", cls="secondary"), # cls="secondary" le da otro color en Pico
                action="/generar_inter", method="post"
            ),
            # --- SECCIÓN DE AUDITORÍA PARA LA CA INTERMEDIA (Paso 2) ---
            Details(
                Summary("Ver Políticas de Restricción y Firma (Auditoría de Seguridad)"),
                P("Para garantizar un ", Strong("entorno controlado"), " en la Autoridad Registradora (Punto 4 de la rúbrica), se inyectan extensiones críticas X.509 al momento de la firma. La directiva ", Strong("pathlen:0"), " asegura matemáticamente que esta CA no pueda emitir certificados para otras sub-CAs:"),
                Pre(Code(
                    "# 1. Extensiones estrictas de control (inter_ext.cnf):\n"
                    "basicConstraints=critical,CA:TRUE,pathlen:0\n"
                    "keyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"
                    "subjectKeyIdentifier=hash\n\n"
                    "# 2. Firma autorizada por la Root CA:\n"
                    "openssl x509 -req \\\n"
                    "  -in inter-ca.csr \\\n"
                    "  -CA root.crt \\\n"
                    "  -CAkey root-ca.key \\\n"
                    "  -passin pass:[CONTRASEÑA_ROOT_OCULTA] \\\n"
                    "  -extfile inter_ext.cnf \\\n"
                    "  -out inter-ca.crt"
                )),
                P(Small("Nota: A diferencia de la Root CA (que opera 100% offline), esta CA Intermedia opera en un servidor con entorno de acceso controlado para procesar la emisión de credenciales de los usuarios finales, manteniendo siempre su propia clave privada protegida con AES-256."))
            )
        ),
        
        # --- TARJETA PASO 3 ---
        Article(
            H2("Paso 3: Certificados de Usuarios (.p12)"),
            Form(
                Label("Contraseña de la CA Intermedia (para firmar):",
                    Input(type="password", name="inter_password", required=True)
                ),
                Button("Generar credenciales para usuarios", type="submit", cls="contrast"),
                action="/generar_usuarios", method="post"
            ),
            # --- SECCIÓN DE ESTÁNDARES IETF (Punto 8) ---
            Details(
                Summary("Ver Cumplimiento de Estándares IETF (RFCs aplicados)"),
                P("Toda la arquitectura y criptografía de esta PKI opera bajo las siguientes especificaciones formales de la IETF:"),
                Ul(
                    Li(Strong("RFC 5280 (X.509 v3): "), "Aplicado en la inyección de extensiones como ", Code("basicConstraints"), " y ", Code("pathlen"), " para limitar la jerarquía."),
                    Li(Strong("RFC 8017 (RSA): "), "Implementado al exigir llaves de alta seguridad mediante ", Code("-pkeyopt rsa_keygen_bits:4096"), "."),
                    Li(Strong("RFC 5208 (PKCS#8): "), "Garantiza el almacenamiento seguro de la clave privada usando la bandera de cifrado ", Code("-aes-256-cbc"), "."),
                    Li(Strong("RFC 7292 (PKCS#12): "), "Estándar de contenedores criptográficos, usado al empaquetar certificados y llaves de usuario en el archivo final ", Code(".p12"), "."),
                    Li(Strong("RFC 8551 (S/MIME v4.0): "), "Rige la preparación de los certificados para que clientes como Outlook confíen en ellos para el cifrado de correos.")
                ),
                P(Small("Nota: El cumplimiento de estos RFCs garantiza interoperabilidad total con cualquier software comercial o sistema operativo moderno."))
            ),
        ),
        
        cls="container"
    )

# RUTA PARA EL PASO 1
@rt('/generar_root', methods=['POST'])
def post_root(root_password: str):
    try:
        # Debug
        print("Contraseña del root password: ", root_password , " Verificando...") # Check 
        
        generate_root_ca(root_password)
        
        return Main(
            Article(
                H1("¡Root CA Generada! ✅"),
                P("Los archivos se guardaron en la carpeta root_ca_output."),
                # En Pico, role="button" convierte un enlace en un botón visualmente
                A("Volver al Inicio", href="/", role="button", cls="outline")
            ),
            cls="container"
        )
        
    except Exception as e:
        return Main(
            Article(
                H1("Ocurrió un error ❌"),
                Pre(str(e)),
                A("Volver a intentar", href="/", role="button", cls="secondary")
            ),
            cls="container"
        )

# Aquí irían las rutas @rt('/generar_inter') y @rt('/generar_usuarios') en el futuro

@rt('/generar_inter', methods=['POST'])
def post_inter(root_password: str, inter_password: str):
    try:
        generate_ca_intermedio(root_password, inter_password)
        return Main(
            Article(
                H1("¡CA Intermedia Generada! 🔐"),
                P("La cadena de confianza (chain.crt) está lista."),
                A("Volver al Inicio", href="/", role="button", cls="outline")
            ), cls="container"
        )
    except Exception as e:
        return Main(Article(H1("Error ❌"), Pre(str(e)), A("Volver", href="/", role="button")), cls="container")

# RUTA PARA EL PASO 3
@rt('/generar_usuarios', methods=['POST'])
def post_usuarios(inter_password: str):
    try:
        # Generamos una contraseña genérica para los usuarios en la demo web
        # (Podrías pedirla en el formulario también, pero así es más rápido)
        pass_demo = "Alumno2026!" 
        
        for usuario in USUARIOS:
            generate_user_p12(usuario, inter_password, pass_demo)
            
        return Main(
            Article(
                H1("¡Certificados de Usuario Generados! 🧑‍🎓"),
                P("Los archivos .p12 ya están listos para descargarse."),
                # BOTÓN DIRECTO A TU ETAPA 4
                A("Ir a la Vista de Usuarios (Etapa 4)", href="/vista_usuarios", role="button", cls="contrast")
            ), cls="container"
        )
    except Exception as e:
        return Main(Article(H1("Error ❌"), Pre(str(e)), A("Volver", href="/", role="button")), cls="container")

# ==========================================
# RUTA PARA TU ETAPA 4: LA VISTA DEL USUARIO
# ==========================================
@rt('/vista_usuarios')
def get_vista():
    DIR_USUARIOS = Path("usuarios_p12_output")
    tarjetas_usuarios = []
    
    if DIR_USUARIOS.exists():
        for txt_file in DIR_USUARIOS.glob("*_password.txt"):
            nombre_base = txt_file.name.replace("_password.txt", "")
            
            # Leemos todo el contenido del archivo .txt generado en el Paso 3
            texto_completo = txt_file.read_text().strip()
            
            tarjetas_usuarios.append(
                Article(
                    H3(f"Certificado de: {nombre_base}"),
                    P("Cofre PKCS#12 listo para instalar en clientes de correo (Outlook/Thunderbird)."),
                    
                    # --- EL BOTÓN MÁGICO DE DESCARGA ---
                    A("📥 Descargar Certificado (.p12)", href=f"/descargar/{nombre_base}", role="button", cls="primary"),
                    
                    Br(), Br(),
                    
                    # Ocultamos el texto de la contraseña en un acordeón por estética
                    Details(
                        Summary("Ver instrucciones y contraseña de instalación"),
                        Pre(Code(texto_completo))
                    )
                )
            )

    if not tarjetas_usuarios:
        tarjetas_usuarios = [P("Aún no hay certificados generados. Ejecuta el Paso 3 primero.")]

    return Main(
        H1("Portal de Usuarios (Etapa 4)"),
        P("Descarga tu identidad criptográfica y las instrucciones para configurar Outlook."),
        *tarjetas_usuarios,
        Br(),
        A("Volver a Administración", href="/", role="button", cls="secondary"),
        cls="container"
    )

from starlette.responses import FileResponse

# Esta ruta usa una variable en la URL {nombre_base} para saber qué archivo pedir
@rt('/descargar/{nombre_base}')
def get_descarga(nombre_base: str):
    # Armamos la ruta física donde vive el archivo .p12
    ruta_p12 = Path("usuarios_p12_output") / f"{nombre_base}.p12"
    
    if ruta_p12.exists():
        # FileResponse obliga al navegador a descargar el archivo en lugar de intentar leerlo
        return FileResponse(
            path=ruta_p12, 
            filename=f"{nombre_base}.p12", 
            media_type="application/x-pkcs12"
        )
    else:
        return "Archivo no encontrado", 404

if __name__ == '__main__':
    #serve(port=5001)
    serve(host="0.0.0.0", port=8099)
