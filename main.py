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
            )
        ),
        
        cls="container"
    )

# RUTA PARA EL PASO 1
@rt('/generar_root', methods=['POST'])
def post_root(root_password: str):
    try:
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
    # Vamos a leer la carpeta para ver qué usuarios ya tienen su certificado
    DIR_USUARIOS = Path("usuarios_p12_output")
    
    tarjetas_usuarios = []
    
    if DIR_USUARIOS.exists():
        # Buscamos todos los archivos .txt de contraseñas para saber quiénes existen
        for txt_file in DIR_USUARIOS.glob("*_password.txt"):
            nombre_base = txt_file.name.replace("_password.txt", "")
            password = txt_file.read_text().strip()
            
            tarjetas_usuarios.append(
                Article(
                    H3(f"Certificado de: {nombre_base}"),
                    P(B("Contraseña de importación: "), Code(password)),
                    P("Usa esta contraseña para instalar el .p12 en tu Outlook."),
                    # Opcional: Podrías hacer una ruta para descargar el archivo físico, 
                    # pero por ahora mostrar la info cumple el requerimiento.
                )
            )

    if not tarjetas_usuarios:
        tarjetas_usuarios = [P("Aún no hay certificados generados. Ejecuta el Paso 3 primero.")]

    return Main(
        H1("Portal de Usuarios (Etapa 4)"),
        P("Aquí los usuarios pueden ver la información para configurar su Outlook."),
        *tarjetas_usuarios,
        Br(),
        A("Volver a Administración", href="/", role="button", cls="secondary"),
        cls="container"
    )


if __name__ == '__main__':
    serve(port=5001)