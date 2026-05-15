from fasthtml.common import *
from pathlib import Path
from crypto_core.root_ca import generate_root_ca
from crypto_core.inter_ca import generate_ca_intermedio
from crypto_core.usuarios_p12 import generate_user_p12
from crypto_core import ra
from crypto_core import ldap_connector

# Configuración de Tailwind y Google Fonts (Lora)
tailwind_config = """
tailwind.config = {
  theme: {
    extend: {
      colors: {
        anahuac: '#FF5900',
        cream: '#F9FAFB',
        charcoal: '#1F2937',
      },
      fontFamily: {
        serif: ['Lora', 'serif'],
      },
    }
  }
}
"""

hdrs = (
    Link(rel="preconnect", href="https://fonts.googleapis.com"),
    Link(rel="preconnect", href="https://fonts.gstatic.com", crossorigin=True),
    Link(href="https://fonts.googleapis.com/css2?family=Lora:ital,wght@0,400..700;1,400..700&display=swap", rel="stylesheet"),
    Script(src="https://cdn.tailwindcss.com"),
    Script(tailwind_config),
    Style("""
        body { font-family: 'Lora', serif; @apply text-charcoal bg-cream; }
        .card-academic { @apply bg-white border border-gray-200 rounded-xl shadow-sm p-8 hover:shadow-md transition-all duration-300 transform hover:-translate-y-1; }
        .btn-anahuac { @apply bg-anahuac text-white font-black py-4 px-8 rounded-xl hover:bg-orange-700 active:scale-95 transition-all shadow-md hover:shadow-lg border-b-4 border-orange-800 flex items-center justify-center; }
        .btn-outline-anahuac { @apply border-2 border-anahuac text-anahuac font-black py-4 px-8 rounded-xl hover:bg-orange-50 active:scale-95 transition-all shadow-sm flex items-center justify-center; }
        
        table { @apply min-w-full divide-y divide-gray-200 border border-gray-200 rounded-xl overflow-hidden mb-8 bg-white shadow-sm; }
        th { @apply px-6 py-4 bg-gray-50 text-left text-xs font-bold text-gray-600 uppercase tracking-widest border-b; }
        td { @apply px-6 py-4 whitespace-nowrap text-sm text-gray-700 border-b; }
        tr:last-child td { border-bottom: 0; }
        tr:hover { @apply bg-orange-50/30 transition-colors; }

        .header-gradient { background: linear-gradient(135deg, #ffffff 0%, #fef3c7 100%); }
    """, type="text/tailwindcss")
)

# Al pasar pico=False y nuestros hdrs, desactivamos Pico CSS
app, rt = fast_app(pico=False, hdrs=hdrs)

# Helpers de UI Académica
def Layout(*args, title="MailGuard PKI", **kwargs):
    return Main(
        Header(
            Div(
                # Logo posicionado en la esquina superior derecha
                Img(src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/a5/Logo_An%C3%A1huac.svg/512px-Logo_An%C3%A1huac.svg.png", 
                    alt="Logo Anáhuac", cls="absolute top-6 right-8 h-20 drop-shadow-sm opacity-90"),
                
                # Contenido central
                Div(
                    H1(title, cls="text-5xl font-serif font-bold text-anahuac mb-4 tracking-tight"),
                    P("Infraestructura de Claves para Correo Institucional S/MIME", 
                      cls="text-charcoal font-medium italic text-xl max-w-2xl mx-auto"),
                    cls="pt-4"
                ),
                cls="container mx-auto px-6 py-16 text-center relative"
            ),
            cls="bg-white border-b-4 border-anahuac mb-12 shadow-md header-gradient relative overflow-hidden"
        ),
        Div(*args, cls="container mx-auto px-6 max-w-7xl pb-24", **kwargs),
        Footer(
            Div(
                P("Universidad Anáhuac México · Facultad de Ingeniería", cls="text-charcoal font-bold text-lg mb-2"),
                P("Proyecto Final: Matemáticas Discretas · Enero - Mayo 2026", cls="text-gray-500 font-medium"),
                cls="container mx-auto px-6 py-12 border-t border-gray-200 mt-auto text-center"
            ),
            cls="bg-white mt-12 shadow-inner"
        ),
        cls="min-h-screen flex flex-col"
    )

def EntityCard(title, subtitle, description, href, icon_svg):
    return A(
        Div(
            Div(NotStr(icon_svg), cls="text-anahuac mb-6 scale-125 origin-left"),
            H3(title, cls="text-3xl font-serif font-black text-charcoal mb-2"),
            P(subtitle, cls="text-anahuac text-sm uppercase tracking-[0.2em] font-black mb-4"),
            P(description, cls="text-gray-600 text-base leading-relaxed font-medium"),
            cls="h-full flex flex-col"
        ),
        href=href,
        cls="card-academic"
    )

# Iconos SVG para las entidades
ICONS = {
    "root": '<svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>',
    "inter": '<svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>',
    "admin": '<svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" /></svg>',
    "user": '<svg xmlns="http://www.w3.org/2000/svg" class="h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>'
}

@rt('/')
def get():
    return Layout(
        Div(
            EntityCard(
                "Root CA", "Autoridad Certificadora Raíz",
                "Establece el ancla de confianza maestra y emite el certificado raíz de la universidad. Diseñado para operar en entornos aislados de alta seguridad.",
                "/root_ca", ICONS["root"]
            ),
            EntityCard(
                "Intermediate CA", "Autoridad Certificadora Intermedia",
                "Entidad operativa encargada de la emisión de certificados de usuario. Protege la clave raíz y gestiona la revocación institucional.",
                "/inter_ca", ICONS["inter"]
            ),
            EntityCard(
                "RA Admin", "Autoridad de Registro (Admin)",
                "Panel de control para administradores. Permite el enrolamiento de usuarios, sincronización AD y monitoreo de la infraestructura.",
                "/admin", ICONS["admin"]
            ),
            EntityCard(
                "User Portal", "Portal del Usuario",
                "Centro de auto-servicio para solicitar credenciales S/MIME, descargar archivos .p12 y consultar guías de instalación.",
                "/vista_usuarios", ICONS["user"]
            ),
            cls="grid grid-cols-1 md:grid-cols-2 gap-10"
        )
    )

@rt('/admin')
def get_admin():
    estado = "Operativa y Desbloqueada ✅" if ra.is_unlocked() else "Bloqueada (Requiere Desbloqueo) 🔒"
    info = ra.session_info()
    desde = info.get("since") if info else "—"

    return Layout(
        A("← Volver al Hub", href="/", cls="text-anahuac font-bold hover:underline mb-6 inline-block"),
        H1("Panel de Administración de la RA", cls="text-4xl font-serif font-black text-charcoal mb-4"),
        P("Gestión centralizada de identidades y supervisión de certificados.", cls="mb-12 text-gray-600 font-medium text-lg"),

        Div(
            _expiry_banner(),
            _validation_banner(),
            cls="mb-12 space-y-6"
        ),

        Div(
            # Estado de la CA
            Div(
                H2("Estado del Sistema", cls="text-2xl font-serif font-black text-charcoal mb-6"),
                Div(
                    P(Strong("Seguridad: "), Span(estado, cls="text-green-600 font-bold" if ra.is_unlocked() else "text-red-600 font-bold")),
                    P(Strong("Actividad: "), "Sesión administrativa desde: ", Code(desde, cls="text-xs font-bold")),
                    cls="space-y-3 text-base"
                ),
                cls="card-academic"
            ),
            
            # Acciones Rápidas
            Div(
                H2("Control de Bóveda", cls="text-2xl font-serif font-black text-charcoal mb-6"),
                Div(
                    Form(
                        Label("Admin Password:", cls="block text-sm font-bold mb-2"),
                        Input(type="password", name="admin_password", required=True, cls="mb-4"),
                        Label("CA Intermedia Password:", cls="block text-sm font-bold mb-2"),
                        Input(type="password", name="inter_password", required=True, cls="mb-4"),
                        Label("Master Password (KRA):", cls="block text-sm font-bold mb-2"),
                        Input(type="password", name="master_password", required=True, cls="mb-6"),
                        Button("Desbloquear CA", type="submit", cls="btn-anahuac w-full"),
                        action="/admin/unlock", method="post"
                    ) if not ra.is_unlocked() else 
                    Form(
                        Label("Confirmar Admin Password:", cls="block text-sm font-bold mb-2"),
                        Input(type="password", name="admin_password", required=True, cls="mb-6"),
                        Button("Bloquear CA", type="submit", cls="w-full bg-charcoal text-white font-bold py-3 rounded-lg hover:bg-black transition-all shadow-lg"),
                        action="/admin/lock", method="post"
                    ),
                    cls="text-sm"
                ),
                cls="card-academic"
            ),
            cls="grid grid-cols-1 md:grid-cols-2 gap-10 mb-12"
        ),

        # Gestión de Usuarios y Sincronización
        Div(
            H2("Gestión de Identidades", cls="text-3xl font-serif font-black text-charcoal mb-8 text-center"),
            Div(
                # Enrolamiento
                Div(
                    H3("Enrolar Usuario Manualmente", cls="text-xl font-serif font-black text-charcoal mb-4"),
                    Form(
                        Label("Admin Password:", cls="block text-xs font-bold mb-1"),
                        Input(type="password", name="admin_password", required=True, cls="mb-3 text-sm"),
                        Label("Email Institucional:", cls="block text-xs font-bold mb-1"),
                        Input(type="email", name="email", placeholder="ejemplo@anahuac.mx", required=True, cls="mb-3 text-sm"),
                        Label("Nombre Completo:", cls="block text-xs font-bold mb-1"),
                        Input(type="text", name="nombre", required=True, cls="mb-3 text-sm"),
                        Label("OU:", cls="block text-xs font-bold mb-1"),
                        Input(type="text", name="org_unit", value="Alumnos", required=True, cls="mb-3 text-sm"),
                        Label("Password Temporal:", cls="block text-xs font-bold mb-1"),
                        Input(type="password", name="user_password", required=True, cls="mb-6 text-sm"),
                        Button("Registrar Usuario", type="submit", cls="btn-anahuac w-full text-sm"),
                        action="/admin/enroll", method="post"
                    ),
                    cls="card-academic"
                ),
                
                # Active Directory & Consultas
                Div(
                    Div(
                        H3("Sincronización AD", cls="text-xl font-serif font-black text-charcoal mb-4"),
                        Form(
                            Input(type="password", name="admin_password", placeholder="Password Admin", required=True, cls="mb-4 text-sm"),
                            Button("Sincronizar con AD", type="submit", cls="btn-outline-anahuac w-full text-sm"),
                            action="/admin/sync_ad", method="post"
                        ),
                        cls="card-academic mb-8"
                    ),
                    Div(
                        H3("Consultas y Bitácoras", cls="text-xl font-serif font-black text-charcoal mb-4"),
                        Div(
                            Form(
                                Input(type="password", name="admin_password", placeholder="Admin Password", required=True, cls="mb-3 text-sm"),
                                Button("📊 Padrón de Usuarios", type="submit", cls="w-full text-left font-bold text-anahuac hover:bg-orange-50 p-2 rounded transition-all"),
                                action="/admin/usuarios", method="post"
                            ),
                            Form(
                                Input(type="password", name="admin_password", placeholder="Admin Password", required=True, cls="mb-3 text-sm"),
                                Button("📜 Bitácora de Emisiones", type="submit", cls="w-full text-left font-bold text-anahuac hover:bg-orange-50 p-2 rounded transition-all"),
                                action="/admin/emisiones", method="post"
                            ),
                            cls="space-y-1"
                        ),
                        cls="card-academic"
                    )
                ),
                cls="grid grid-cols-1 md:grid-cols-2 gap-10"
            )
        ),
        title="Admin Portal"
    )

@rt('/root_ca')
def get_root_ca():
    return Layout(
        A("← Volver al Hub", href="/", cls="text-anahuac font-bold hover:underline mb-8 inline-block"),
        Div(
            H2("Configuración de la Root CA", cls="text-4xl font-serif font-black text-charcoal mb-6"),
            P("Este proceso genera la clave privada RSA-4096 y el certificado raíz autofirmado institucional.", cls="text-lg text-gray-600 mb-10"),
            
            Div(
                Form(
                    Div(
                        Label("Contraseña para la Root CA:", cls="block text-sm font-bold text-gray-700 mb-3"),
                        Input(type="password", name="root_password", required=True)
                    ),
                    Button("Generar Root CA", type="submit", cls="btn-anahuac w-full mt-8"),
                    action="/generar_root", method="post"
                ),
                cls="card-academic max-w-2xl mx-auto"
            ),
            
            # Auditoría
            Div(
                Details(
                    Summary("🔍 Especificaciones Técnicas (Auditoría)", cls="cursor-pointer font-bold text-anahuac hover:underline mt-12"),
                    Div(
                        P("Algoritmo: RSA 4096 bits. Cifrado de llave: AES-256-CBC.", cls="mt-6 mb-4 font-bold"),
                        Pre("openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes-256-cbc -out root-ca.key", 
                            cls="bg-gray-900 text-white p-6 rounded-xl text-xs overflow-x-auto shadow-xl"),
                        cls="p-8 bg-white mt-4 rounded-2xl border border-gray-100 shadow-inner"
                    )
                ),
                cls="max-w-2xl mx-auto"
            )
        ),
        title="Configuración Root CA"
    )

@rt('/inter_ca')
def get_inter_ca():
    return Layout(
        A("← Volver al Hub", href="/", cls="text-anahuac font-bold hover:underline mb-8 inline-block"),
        Div(
            H2("Configuración de la CA Intermedia", cls="text-4xl font-serif font-black text-charcoal mb-6"),
            P("Vínculo entre la Raíz y los usuarios finales. Requiere la llave de la Root CA para ser firmada.", cls="text-lg text-gray-600 mb-10"),
            
            Div(
                Form(
                    Label("Contraseña de la Root CA:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="password", name="root_password", required=True, cls="mb-4"),
                    
                    Label("Nueva contraseña para la CA Intermedia:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="password", name="inter_password", required=True, cls="mb-4"),
                    
                    Label("Master password para escrow (KRA):", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="password", name="master_password", required=True, cls="mb-6"),
                    
                    Button("Generar CA Intermedia", type="submit", cls="btn-anahuac w-full"),
                    action="/generar_inter", method="post"
                ),
                cls="card-academic max-w-2xl mx-auto mb-16"
            ),
            
            Div(
                H3("Gestión Operativa", cls="text-xl font-serif font-black text-charcoal mb-6 text-center"),
                Div(
                    A("🛡️ Revocar Certificado", href="#revocacion", cls="btn-outline-anahuac text-center flex-1"),
                    A("🔑 Recuperación KRA", href="#kra", cls="btn-outline-anahuac text-center flex-1"),
                    cls="flex flex-col md:flex-row gap-4 max-w-2xl mx-auto"
                ),
                cls="mt-12"
            )
        ),
        
        Div(
            H3("Módulo de Revocación", id="revocacion", cls="text-3xl font-serif font-black text-charcoal mt-24 mb-8"),
            Div(
                Form(
                    Label("Contraseña de la CA Intermedia:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="password", name="inter_password", required=True, cls="mb-4"),
                    Label("Nombre base del usuario (Filename):", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="text", name="cert_filename", placeholder="ej: jaime_chuma", required=True, cls="mb-4"),
                    Label("Motivo de la revocación:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Select(
                        Option("unspecified", value="unspecified"),
                        Option("keyCompromise", value="keyCompromise"),
                        Option("affiliationChanged", value="affiliationChanged"),
                        Option("superseded", value="superseded"),
                        name="motivo", cls="mb-8 cursor-pointer"
                    ),
                    Button("Revocar Certificado", type="submit", cls="btn-anahuac w-full"),
                    action="/revocar", method="post"
                ),
                cls="card-academic max-w-2xl mx-auto"
            ),
            H3("Módulo de Recuperación (KRA)", id="kra", cls="text-3xl font-serif font-black text-charcoal mt-24 mb-8"),
            Div(
                Form(
                    Label("Master password de escrow:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="password", name="master_password", required=True, cls="mb-4"),
                    Label("Nombre base del usuario:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="text", name="cert_filename", required=True, cls="mb-4"),
                    Label("Nueva contraseña para el .p12:", cls="block text-sm font-bold text-gray-700 mb-2"),
                    Input(type="password", name="new_p12_password", required=True, cls="mb-8"),
                    Button("Recuperar .p12", type="submit", cls="btn-anahuac w-full"),
                    action="/recover", method="post"
                ),
                cls="card-academic max-w-2xl mx-auto"
            ),
            cls="container mx-auto"
        )
    )

# RUTA PARA EL PASO 1
@rt('/generar_root', methods=['POST'])
def post_root(root_password: str):
    try:
        generate_root_ca(root_password)
        return Layout(Div(H1("¡Root CA Generada! ✅", cls="text-3xl font-serif font-bold text-charcoal mb-4"), P("Los archivos se han guardado exitosamente en root_ca_output.", cls="mb-8 text-gray-600"), A("Volver al Inicio", href="/", cls="btn-anahuac inline-block"), cls="text-center py-12"))
    except Exception as e:
        return Layout(Div(H1("Error en Generación ❌", cls="text-2xl font-serif font-bold text-red-600 mb-4"), Pre(str(e), cls="bg-red-50 p-4 border rounded mb-8 text-sm overflow-x-auto"), A("Volver", href="/root_ca", cls="btn-anahuac inline-block"), cls="text-center py-12"))

@rt('/generar_inter', methods=['POST'])
def post_inter(root_password: str, inter_password: str, master_password: str):
    try:
        generate_ca_intermedio(root_password, inter_password, master_password)
        return Layout(Div(H1("¡CA Intermedia Generada! 🔐", cls="text-3xl font-serif font-bold text-charcoal mb-4"), P("La cadena de confianza está lista.", cls="mb-4 text-gray-600"), A("Volver al Inicio", href="/", cls="btn-anahuac inline-block"), cls="text-center py-12"))
    except Exception as e:
        return Layout(Div(H1("Error en Generación ❌", cls="text-2xl font-serif font-bold text-red-600 mb-4"), Pre(str(e), cls="bg-red-50 p-4 border rounded mb-8 text-sm overflow-x-auto"), A("Volver", href="/inter_ca", cls="btn-anahuac inline-block"), cls="text-center py-12"))

def _expiry_banner():
    s = ra.expiry_summary()
    if s["total_active"] == 0: return ""
    return Div(H4("⚠ Certificados Próximos a Expirar", cls="font-bold text-orange-800 mb-2"), Form(Div(Input(type="password", name="admin_password", placeholder="Password Admin", required=True, cls="p-2 border rounded text-xs mr-2 text-charcoal"), Button("Ver Dashboard", type="submit", cls="bg-orange-600 text-white px-3 py-2 rounded text-xs font-bold hover:bg-orange-700 transition-colors"), cls="flex items-center"), action="/admin/expiraciones", method="post"), cls="bg-orange-50 border-l-4 border-orange-500 p-4 rounded shadow-sm")

def _validation_banner():
    s = ra.count_validation_failures()
    if s["total_active"] == 0: return ""
    return Div(H4("⚠ Problemas de Validación Detectados", cls="font-bold text-red-800 mb-2"), Form(Div(Input(type="password", name="admin_password", placeholder="Password Admin", required=True, cls="p-2 border rounded text-xs mr-2 text-charcoal"), Button("Re-validar Todo", type="submit", cls="bg-red-600 text-white px-3 py-2 rounded text-xs font-bold hover:bg-red-700 transition-colors"), cls="flex items-center"), action="/admin/validacion_global", method="post"), cls="bg-red-50 border-l-4 border-red-500 p-4 rounded shadow-sm")

def _admin_error(msg: str):
    return Layout(Div(H1("Error ❌", cls="text-2xl font-bold text-red-600 mb-4"), Pre(str(msg), cls="bg-red-50 p-4 border rounded mb-6 text-sm overflow-x-auto text-red-800"), A("Volver al Panel", href="/admin", cls="btn-anahuac inline-block"), cls="max-w-2xl mx-auto text-center py-12"), title="Error Admin")

@rt('/admin/unlock', methods=['POST'])
def post_admin_unlock(admin_password: str, inter_password: str, master_password: str):
    try:
        ra.admin_unlock(admin_password, inter_password, master_password)
        return Layout(Div(H1("CA Desbloqueada ✅", cls="text-3xl font-bold text-charcoal mb-4"), A("Volver al Panel", href="/admin", cls="btn-anahuac inline-block"), cls="text-center py-12"))
    except Exception as e: return _admin_error(e)

@rt('/admin/lock', methods=['POST'])
def post_admin_lock(admin_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    ra.admin_lock()
    return Layout(Div(H1("CA Bloqueada 🔒", cls="text-3xl font-bold text-charcoal mb-4"), A("Volver al Panel", href="/admin", cls="btn-anahuac inline-block"), cls="text-center py-12"))

@rt('/admin/enroll', methods=['POST'])
def post_admin_enroll(admin_password: str, email: str, nombre: str, org_unit: str, user_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    try:
        ra.enroll_user(email, nombre, org_unit, user_password)
        return Layout(Div(H1("Usuario Enrolado ✅", cls="text-3xl font-bold text-charcoal mb-6"), A("Volver al Panel", href="/admin", cls="btn-anahuac inline-block"), cls="text-center py-12"))
    except Exception as e: return _admin_error(e)

@rt('/admin/sync_ad', methods=['POST'])
def post_admin_sync_ad(admin_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    try:
        ldap_connector.sync_ad_to_ra(dry_run=False)
        return Layout(Div(H1("Sincronización AD Completada ✅", cls="text-3xl font-bold text-charcoal mb-6"), A("Volver al Panel", href="/admin", cls="btn-anahuac inline-block"), cls="text-center py-12"))
    except Exception as e: return _admin_error(e)

@rt('/admin/usuarios', methods=['POST'])
def post_admin_usuarios(admin_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    usuarios = ra.list_users()
    filas = [Tr(Th("ID"), Th("Email"), Th("Nombre"), Th("Filename"), Th("Estado"))]
    for u in usuarios: filas.append(Tr(Td(str(u["id"])), Td(u["email"]), Td(u["nombre"]), Td(Code(u["filename"], cls="text-xs")), Td(u["status"])))
    return Layout(A("← Volver", href="/admin", cls="text-anahuac hover:underline mb-4 inline-block"), H1("Padrón de Usuarios", cls="text-3xl font-bold text-charcoal mb-6"), Div(Table(*filas), cls="overflow-x-auto"))

@rt('/admin/emisiones', methods=['POST'])
def post_admin_emisiones(admin_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    emisiones = ra.list_emissions()
    filas = [Tr(Th("ID"), Th("Fecha"), Th("Email"), Th("Filename"))]
    for e in emisiones: filas.append(Tr(Td(str(e["id"])), Td(e["issued_at"][:16]), Td(e["email"]), Td(Code(e["filename"], cls="text-xs"))))
    return Layout(A("← Volver", href="/admin", cls="text-anahuac hover:underline mb-4 inline-block"), H1("Bitácora de Emisiones", cls="text-3xl font-bold text-charcoal mb-6"), Div(Table(*filas), cls="overflow-x-auto"))

@rt('/admin/expiraciones', methods=['POST'])
def post_admin_expiraciones(admin_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    emisiones = ra.list_emissions_with_status()
    filas = [Tr(Th("ID"), Th("Email"), Th("Días"), Th("Vence"), Th("Status"))]
    for e in emisiones: filas.append(Tr(Td(str(e["id"])), Td(e["email"]), Td(str(e["days_remaining"])), Td((e["expires_at"] or "—")[:10]), Td(e["status"])))
    return Layout(A("← Volver", href="/admin", cls="text-anahuac hover:underline mb-4 inline-block"), H1("Expiraciones", cls="text-3xl font-bold text-charcoal mb-4"), Div(Table(*filas), cls="overflow-x-auto"))

@rt('/admin/validacion_global', methods=['POST'])
def post_admin_validacion_global(admin_password: str):
    if not ra.verify_admin(admin_password): return _admin_error("Admin password incorrecto.")
    from crypto_core.validation import revalidate_all_active
    reports = revalidate_all_active()
    filas = [Tr(Th("Filename"), Th("Resultado"))]
    for r in reports: filas.append(Tr(Td(Code(r["filename"], cls="text-xs")), Td(r["email"]), Td(r["overall"].upper())))
    return Layout(A("← Volver", href="/admin", cls="text-anahuac hover:underline mb-4 inline-block"), H1("Validación Global", cls="text-3xl font-bold text-charcoal mb-6"), Div(Table(*filas), cls="overflow-x-auto"))

@rt('/solicitar')
def get_solicitar():
    estado_msg = Div(P("✅ Autoridad Desbloqueada", cls="text-green-800 font-bold"), cls="bg-green-50 border-l-4 border-green-500 p-3 mb-6") if ra.is_unlocked() else Div(P("🔒 Autoridad Bloqueada", cls="text-red-800 font-bold"), cls="bg-red-50 border-l-4 border-red-500 p-3 mb-6")
    return Layout(
        A("← Volver", href="/vista_usuarios", cls="text-anahuac hover:underline mb-4 inline-block"),
        H1("Solicitar Certificado S/MIME", cls="text-4xl font-serif font-bold text-charcoal mb-4"),
        estado_msg,
        Div(Form(Label("Email Institucional:", cls="block text-sm font-bold mb-1"), Input(type="email", name="email", placeholder="ej: nombre.apellido@anahuac.mx", required=True, cls="mb-4"), Label("Password Personal (RA):", cls="block text-sm font-bold mb-1"), Input(type="password", name="user_password", required=True, cls="mb-4"), Label("Password para el .p12:", cls="block text-sm font-bold mb-1"), Input(type="password", name="p12_password", required=True, minlength="8", cls="mb-6"), Button("Emitir mi Identidad Digital", type="submit", cls="btn-anahuac w-full"), action="/solicitar", method="post"), cls="card-academic max-w-xl mx-auto"),
        title="Solicitar Certificado"
    )

@rt('/solicitar', methods=['POST'])
def post_solicitar(req, email: str, user_password: str, p12_password: str):
    try:
        if not ra.is_unlocked(): raise RuntimeError("La CA está bloqueada.")
        usuario = ra.authenticate_user(email, user_password)
        inter_pw, master_pw = ra.get_session_passwords()
        prev_emission = ra.get_active_emission(usuario["id"])
        is_renewal = prev_emission is not None
        usuario_dict = {"nombre": usuario["nombre"], "email": usuario["email"], "filename": usuario["filename"]}
        generate_user_p12(usuario_dict, inter_pw, p12_password, master_pw)
        cert_path = Path("usuarios_p12_output") / f"{usuario['filename']}.crt"
        metadata = ra.extract_cert_metadata(cert_path)
        ip = req.client.host if req.client else None
        new_emission_id = ra.record_emission(usuario["id"], usuario["filename"], expires_at=metadata["expires_at"], serial=metadata["serial"], ip=ip, supersedes=prev_emission["id"] if is_renewal else None)
        return Layout(Div(H1("Certificado Emitido ✅", cls="text-3xl font-bold text-charcoal mb-4"), Div(P(Strong("Vencimiento: "), metadata["expires_at"][:10]), P(Strong("Serie: "), Code(metadata["serial"], cls="text-xs")), cls="mb-8 p-4 bg-gray-50 border rounded text-sm space-y-2"), A("📦 Descargar Bundle Thunderbird", href=f"/descargar_bundle/{usuario['filename']}", cls="btn-anahuac block text-center mb-4"), A("Volver", href="/", cls="text-anahuac hover:underline font-bold text-sm block text-center"), cls="max-w-2xl mx-auto"), title="Certificado Emitido")
    except Exception as e: return Layout(Div(H1("Error ❌", cls="text-2xl font-bold text-red-600 mb-4"), Pre(str(e), cls="bg-red-50 p-4 border rounded mb-8 text-sm overflow-x-auto text-red-800"), A("Volver", href="/solicitar", cls="btn-anahuac inline-block"), cls="text-center py-12"), title="Solicitud Fallida")

@rt('/vista_usuarios')
def get_vista():
    DIR_USUARIOS = Path("usuarios_p12_output")
    tarjetas = []
    if DIR_USUARIOS.exists():
        for p12 in sorted(DIR_USUARIOS.glob("*.p12")):
            tarjetas.append(Div(H3(f"Usuario: {p12.stem}", cls="text-lg font-bold text-charcoal mb-4"), A("📦 Descargar Bundle", href=f"/descargar_bundle/{p12.stem}", cls="btn-anahuac block text-center text-xs"), cls="card-academic"))
    return Layout(A("← Volver", href="/", cls="text-anahuac font-bold hover:underline mb-4 inline-block"), H1("Portal de Usuarios", cls="text-4xl font-serif font-black text-charcoal mb-8"), Div(*tarjetas if tarjetas else [P("Sin certificados.")], cls="grid grid-cols-1 md:grid-cols-3 gap-6"), title="Portal de Usuarios")

@rt('/descargar/{nombre_base}')
def get_descarga(nombre_base: str):
    ruta = Path("usuarios_p12_output") / f"{nombre_base}.p12"
    if ruta.exists(): return FileResponse(path=ruta, filename=f"{nombre_base}.p12", media_type="application/x-pkcs12")
    return "Archivo no encontrado", 404

@rt('/validar/{filename}')
def get_validar(filename: str):
    from crypto_core.validation import validate_user_cert
    report = validate_user_cert(filename)
    return Layout(H1(f"Validación: {filename}", cls="text-2xl font-bold mb-6"), Pre(str(report), cls="bg-gray-50 p-6 rounded"), title="Validación")

@rt('/descargar_root')
def get_descargar_root():
    ruta = Path("root_ca_output/root.crt")
    if ruta.exists(): return FileResponse(path=ruta, filename="MailGuard-RootCA.crt", media_type="application/x-x509-ca-cert")
    return "No disponible", 404

@rt('/descargar_bundle/{filename}')
def get_descargar_bundle(filename: str):
    try:
        from crypto_core.bundle import build_thunderbird_bundle
        return Response(content=build_thunderbird_bundle(filename), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{filename}_thunderbird.zip"'})
    except Exception as e: return "Error en bundle", 500

@rt('/guia_thunderbird')
def get_guia_thunderbird():
    return Layout(H1("Guía Thunderbird", cls="text-3xl font-bold mb-8"), P("1. Importa Root CA. 2. Importa .p12. 3. Configura S/MIME."), title="Guía")

@rt('/crl/inter-ca.crl')
def get_crl():
    ruta = Path("ca_intermedia_output/crl/inter-ca.crl")
    if ruta.exists(): return FileResponse(path=ruta, media_type="application/pkix-crl")
    return "No disponible", 404

@rt('/revocar', methods=['POST'])
def post_revocar(inter_password: str, cert_filename: str, motivo: str = "unspecified"):
    try:
        from crypto_core.crl import revocar_certificado
        revocar_certificado(str(Path("usuarios_p12_output") / f"{cert_filename}.crt"), inter_password, motivo)
        return Layout(Div(H1("Revocado ✅", cls="text-3xl font-bold mb-4"), A("Volver", href="/inter_ca", cls="btn-anahuac inline-block"), cls="text-center py-12"))
    except Exception as e: return _admin_error(e)

@rt('/recuperar', methods=['POST'])
def post_recuperar(master_password: str, cert_filename: str, new_p12_password: str):
    try:
        from crypto_core.escrow import recover_with_new_password
        return Response(content=recover_with_new_password(cert_filename, master_password, new_p12_password), media_type="application/x-pkcs12", headers={"Content-Disposition": f'attachment; filename="{cert_filename}_recovered.p12"'})
    except Exception as e: return _admin_error(e)

@rt('/escrow_audit')
def get_escrow_audit():
    from crypto_core.escrow import read_audit_log
    return Layout(H1("Auditoría KRA", cls="text-2xl font-bold mb-6"), Pre(read_audit_log(), cls="bg-gray-800 text-white p-6 rounded shadow-lg text-xs overflow-x-auto"), title="Auditoría KRA")

if __name__ == '__main__': serve(host="0.0.0.0", port=8099)
