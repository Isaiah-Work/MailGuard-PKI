from fasthtml.common import *

# IMPORTAMOS TUS FUNCIONES DESDE LA CARPETA crypto_core
from crypto_core.root_ca import *
# from crypto_core.inter_ca import *
# from crypto_core.usuarios_p12 import *

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

if __name__ == '__main__':
    serve(port=5001)