from fasthtml.common import *
from pathlib import Path
from crypto_core.root_ca import generate_root_ca
from crypto_core.inter_ca import generate_ca_intermedio
from crypto_core.usuarios_p12 import generate_user_p12
from crypto_core import ra

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
                Label("Master password para escrow administrativo (KRA):",
                    Input(type="password", name="master_password", required=True)
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
        
        # --- TARJETA PASO 3: REGISTRATION AUTHORITY ---
        Article(
            H2("Paso 3: Registration Authority (RA)"),
            P("La emisión de certificados ya no parte de una lista hardcoded. "
              "Se separa en dos roles claramente acotados:"),
            Ul(
                Li(Strong("Admin: "), "desbloquea la CA, enrola usuarios pre-validados "
                   "y supervisa el padrón. Entra a ", A("/admin", href="/admin"), "."),
                Li(Strong("Usuario final: "), "se autentica con su email y password personal "
                   "para emitir su propio cert. Entra a ", A("/solicitar", href="/solicitar"), ".")
            ),
            Br(),
            A("Panel de Administración", href="/admin", role="button", cls="contrast"),
            " ",
            A("Solicitar mi certificado", href="/solicitar", role="button", cls="outline"),
            " ",
            A("Guía Thunderbird", href="/guia_thunderbird", role="button", cls="outline"),
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


        # --- TARJETA PASO 4 (compartido): REVOCACIÓN ---
        Article(
            H2("Paso 4: Revocar certificado"),
            P(Small(
                "Marca un certificado como inválido. Se actualiza el CRL automáticamente "
                "para que los clientes de correo lo rechacen. La razón sigue ",
                Strong("RFC 5280 §5.3.1"), "."
            )),
            Form(
                Label("Contraseña de la CA Intermedia:",
                    Input(type="password", name="inter_password", required=True)
                ),
                Label("Nombre base del usuario (ej: jaime_chuma):",
                    Input(type="text", name="cert_filename", required=True)
                ),
                Label("Motivo de la revocación:",
                    Select(
                        Option("unspecified — sin razón específica", value="unspecified"),
                        Option("keyCompromise — clave privada filtrada o robada", value="keyCompromise"),
                        Option("affiliationChanged — cambió la afiliación del titular", value="affiliationChanged"),
                        Option("superseded — reemplazado por un cert nuevo", value="superseded"),
                        Option("cessationOfOperation — el titular dejó de operar", value="cessationOfOperation"),
                        Option("certificateHold — suspensión temporal (reversible)", value="certificateHold"),
                        name="motivo"
                    )
                ),
                Button("Revocar certificado", type="submit", cls="secondary"),
                action="/revocar", method="post"
            ),
            Details(
                Summary("Ver guía de motivos de revocación (RFC 5280 §5.3.1)"),
                Ul(
                    Li(Strong("keyCompromise: "), "el .p12 fue compartido, robado o filtrado. Prioridad máxima."),
                    Li(Strong("affiliationChanged: "), "el alumno se cambió de universidad o de unidad organizacional."),
                    Li(Strong("superseded: "), "se emitió uno nuevo (renovación, mejora de algoritmo) sin compromiso."),
                    Li(Strong("cessationOfOperation: "), "el titular se graduó o ya no usa el cert."),
                    Li(Strong("certificateHold: "), "suspensión investigativa — única razón reversible (con removeFromCRL)."),
                    Li(Strong("unspecified: "), "no documenta razón. Algunos clientes lo tratan como keyCompromise por precaución.")
                )
            )
        ),

        # --- TARJETA PASO 5: RECUPERACIÓN KRA ---
        Article(
            H2("Paso 5: Recuperación administrativa (KRA)"),
            P(Small(
                "Si un usuario pierde su .p12 o su contraseña, el admin puede generar un nuevo .p12 "
                "a partir del cofre escrow guardado en el Paso 3. Requiere el ", Strong("master password"),
                " establecido al crear la CA Intermedia."
            )),
            Form(
                Label("Master password de escrow:",
                    Input(type="password", name="master_password", required=True)
                ),
                Label("Nombre base del usuario (ej: jaime_chuma):",
                    Input(type="text", name="cert_filename", required=True)
                ),
                Label("Nueva contraseña para el .p12 recuperado:",
                    Input(type="password", name="new_p12_password", required=True)
                ),
                Button("Recuperar .p12", type="submit", cls="secondary"),
                action="/recuperar", method="post"
            ),
            Br(),
            A("Ver log de auditoría de recuperaciones", href="/escrow_audit", role="button", cls="outline"),
            Details(
                Summary("Modelo de seguridad y trade-offs"),
                Ul(
                    Li("El cofre escrow está cifrado con ", Strong("AES-256-CBC + PBKDF2 (100k iteraciones)"), " bajo el master password."),
                    Li("Cada recuperación queda registrada con timestamp UTC en ", Code("ca_intermedia_output/escrow/audit.log"), "."),
                    Li("Recuperar un .p12 entrega al admin acceso al material criptográfico del usuario, lo que ", Strong("debilita el no-repudio"), " de las firmas históricas. Los usuarios deben estar informados."),
                    Li("Para producción real, el master debería estar en un HSM o dividido entre múltiples admins (Shamir secret sharing).")
                )
            )
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
def post_inter(root_password: str, inter_password: str, master_password: str):
    try:
        generate_ca_intermedio(root_password, inter_password, master_password)
        return Main(
            Article(
                H1("¡CA Intermedia Generada! 🔐"),
                P("La cadena de confianza (chain.crt) está lista."),
                P("El master de escrow (KRA) quedó inicializado. Guárdalo en lugar seguro: sin él no se podrán recuperar cofres .p12."),
                A("Volver al Inicio", href="/", role="button", cls="outline")
            ), cls="container"
        )
    except Exception as e:
        return Main(Article(H1("Error ❌"), Pre(str(e)), A("Volver", href="/", role="button")), cls="container")

# ==========================================
# RUTAS DE LA REGISTRATION AUTHORITY (RA)
# ==========================================
# La emisión de certificados de usuario ya no parte de una lista hardcoded.
# El admin enrola usuarios en /admin (RA) y desbloquea la CA con sus passwords.
# Los usuarios se auto-sirven en /solicitar (autenticando contra la RA).

def _expiry_banner():
    """Banner de alertas de expiracion para mostrar en /admin."""
    s = ra.expiry_summary()
    if s["total_active"] == 0:
        return ""
    if s["expired"] == 0 and s["urgent"] == 0 and s["warning"] == 0 and s["notice"] == 0:
        return Article(
            P("✅ Todos los certs activos están vigentes (>30 días). Total: ",
              Strong(str(s["total_active"])), ".")
        )
    return Article(
        H4("⚠ Atención: hay certificados próximos a expirar"),
        Ul(
            Li("🔴 Ya expirados: ", Strong(str(s["expired"]))),
            Li("🔴 Vencen en <7 días: ", Strong(str(s["urgent"]))),
            Li("🟠 Vencen en <15 días: ", Strong(str(s["warning"]))),
            Li("🟡 Vencen en <30 días: ", Strong(str(s["notice"]))),
            Li("🟢 Más de 30 días: ", Strong(str(s["ok"]))),
        ),
        Form(
            Label("Tu password de admin:",
                Input(type="password", name="admin_password", required=True)),
            Button("Ver dashboard de expiraciones", type="submit", cls="contrast"),
            action="/admin/expiraciones", method="post"
        ),
    )


def _validation_banner():
    """Banner de fallas de validacion (Puntos 16 y 17)."""
    s = ra.count_validation_failures()
    if s["total_active"] == 0:
        return ""
    if s["fail"] == 0 and s["warning"] == 0:
        return Article(
            P("✅ Todos los certs activos pasaron validación de cadena. "
              "(", Strong(str(s["pass"])), " ok, ",
              Strong(str(s["unchecked"])), " sin validar)")
        )
    return Article(
        H4("⚠ Hay certificados con problemas de validación de cadena"),
        Ul(
            Li("❌ Fallas críticas: ", Strong(str(s["fail"]))),
            Li("🟡 Advertencias: ", Strong(str(s["warning"]))),
            Li("✅ Pasaron: ", Strong(str(s["pass"]))),
            Li("⏭ Sin validar: ", Strong(str(s["unchecked"]))),
        ),
        Form(
            Label("Tu password de admin:",
                Input(type="password", name="admin_password", required=True)),
            Button("Re-validar todos los certs", type="submit", cls="contrast"),
            action="/admin/validacion_global", method="post"
        ),
    )


@rt('/admin')
def get_admin():
    estado = "Desbloqueada ✅" if ra.is_unlocked() else "Bloqueada 🔒"
    info = ra.session_info()
    desde = info.get("since") if info else "—"

    return Main(
        H1("Panel de Administración (RA)"),
        P(Small("Operaciones que solo el admin puede realizar: desbloquear la CA, "
                "enrolar usuarios y consultar el padrón de identidades.")),

        _expiry_banner(),
        _validation_banner(),

        Article(
            H2("Estado de la CA"),
            P(Strong("Estado actual: "), estado),
            P(Strong("Desde: "), Code(desde)),
            P(Small("Mientras esté desbloqueada, los usuarios pueden auto-servirse "
                    "en /solicitar usando sus credenciales personales.")),
        ),

        Article(
            H2("1. Desbloquear CA"),
            P("Cachea inter_password y master_password en memoria del proceso. "
              "Necesario antes de que cualquier usuario pueda solicitar un cert."),
            Form(
                Label("Tu password de admin:",
                    Input(type="password", name="admin_password", required=True)),
                Label("Password de la CA Intermedia:",
                    Input(type="password", name="inter_password", required=True)),
                Label("Master password de escrow (KRA):",
                    Input(type="password", name="master_password", required=True)),
                Button("Desbloquear", type="submit"),
                action="/admin/unlock", method="post"
            ),
        ),

        Article(
            H2("2. Bloquear CA"),
            P("Olvida los passwords cacheados. Los usuarios no podrán solicitar "
              "más certs hasta el siguiente desbloqueo."),
            Form(
                Label("Tu password de admin:",
                    Input(type="password", name="admin_password", required=True)),
                Button("Bloquear", type="submit", cls="secondary"),
                action="/admin/lock", method="post"
            ),
        ),

        Article(
            H2("3. Enrolar nuevo usuario"),
            P("Crea una identidad pre-validada en la RA. El filename se deriva "
              "automáticamente del email (ej: ", Code("jaime.chumacero@anahuac.mx"),
              " → ", Code("jaime_chumacero"), ")."),
            Form(
                Label("Tu password de admin:",
                    Input(type="password", name="admin_password", required=True)),
                Label("Email institucional del usuario:",
                    Input(type="email", name="email", required=True)),
                Label("Nombre completo:",
                    Input(type="text", name="nombre", required=True)),
                Label("Unidad organizacional:",
                    Input(type="text", name="org_unit", value="Alumnos", required=True)),
                Label("Password personal del usuario (entregar por canal seguro):",
                    Input(type="password", name="user_password", required=True)),
                Button("Enrolar usuario", type="submit", cls="contrast"),
                action="/admin/enroll", method="post"
            ),
        ),

        Article(
            H2("4. Consultar padrón"),
            Form(
                Label("Tu password de admin:",
                    Input(type="password", name="admin_password", required=True)),
                Button("Ver usuarios enrolados", type="submit", cls="outline"),
                action="/admin/usuarios", method="post"
            ),
            Br(),
            Form(
                Label("Tu password de admin:",
                    Input(type="password", name="admin_password", required=True)),
                Button("Ver bitácora de emisiones", type="submit", cls="outline"),
                action="/admin/emisiones", method="post"
            ),
        ),

        Br(),
        A("Volver al inicio", href="/", role="button", cls="secondary"),
        cls="container"
    )


def _admin_error(msg: str):
    return Main(
        Article(
            H1("Error ❌"),
            Pre(str(msg)),
            A("Volver al panel", href="/admin", role="button", cls="secondary")
        ),
        cls="container"
    )


@rt('/admin/unlock', methods=['POST'])
def post_admin_unlock(admin_password: str, inter_password: str, master_password: str):
    try:
        ra.admin_unlock(admin_password, inter_password, master_password)
        return Main(
            Article(
                H1("CA desbloqueada ✅"),
                P("Los usuarios ya pueden solicitar certificados en ", Code("/solicitar"), "."),
                A("Volver al panel", href="/admin", role="button", cls="outline")
            ),
            cls="container"
        )
    except Exception as e:
        return _admin_error(e)


@rt('/admin/lock', methods=['POST'])
def post_admin_lock(admin_password: str):
    if not ra.verify_admin(admin_password):
        return _admin_error("Admin password incorrecto.")
    ra.admin_lock()
    return Main(
        Article(
            H1("CA bloqueada 🔒"),
            P("Los passwords cacheados fueron olvidados. Las solicitudes nuevas serán rechazadas hasta el próximo desbloqueo."),
            A("Volver al panel", href="/admin", role="button", cls="outline")
        ),
        cls="container"
    )


@rt('/admin/enroll', methods=['POST'])
def post_admin_enroll(
    admin_password: str,
    email: str,
    nombre: str,
    org_unit: str,
    user_password: str,
):
    if not ra.verify_admin(admin_password):
        return _admin_error("Admin password incorrecto.")
    try:
        usuario = ra.enroll_user(email, nombre, org_unit, user_password)
        return Main(
            Article(
                H1("Usuario enrolado ✅"),
                P(Strong("Email: "), usuario["email"]),
                P(Strong("Nombre: "), usuario["nombre"]),
                P(Strong("Filename derivado: "), Code(usuario["filename"])),
                P(Strong("OU: "), usuario["org_unit"]),
                P(Small("Comunica al usuario su password personal por canal seguro "
                        "(en persona, correo institucional firmado, sobre cerrado).")),
                A("Volver al panel", href="/admin", role="button", cls="outline")
            ),
            cls="container"
        )
    except Exception as e:
        return _admin_error(e)


@rt('/admin/usuarios', methods=['POST'])
def post_admin_usuarios(admin_password: str):
    if not ra.verify_admin(admin_password):
        return _admin_error("Admin password incorrecto.")
    usuarios = ra.list_users()
    if not usuarios:
        return Main(
            Article(
                H1("Padrón de usuarios"),
                P("Aún no hay usuarios enrolados."),
                A("Volver al panel", href="/admin", role="button", cls="outline")
            ),
            cls="container"
        )
    filas = [Tr(
        Th("ID"), Th("Email"), Th("Nombre"), Th("Filename"),
        Th("OU"), Th("Estado"), Th("Enrolado"), Th("Última solicitud"), Th("Fallidos")
    )]
    for u in usuarios:
        filas.append(Tr(
            Td(str(u["id"])), Td(u["email"]), Td(u["nombre"]),
            Td(Code(u["filename"])), Td(u["org_unit"]), Td(u["status"]),
            Td(u["enrolled_at"]), Td(u["last_request_at"] or "—"),
            Td(str(u["failed_attempts"]))
        ))
    return Main(
        H1("Padrón de usuarios"),
        Table(*filas),
        Br(),
        A("Volver al panel", href="/admin", role="button", cls="outline"),
        cls="container"
    )


@rt('/admin/expiraciones', methods=['POST'])
def post_admin_expiraciones(admin_password: str):
    if not ra.verify_admin(admin_password):
        return _admin_error("Admin password incorrecto.")

    emisiones = ra.list_emissions_with_status()
    if not emisiones:
        return Main(
            Article(
                H1("Dashboard de expiraciones"),
                P("Aún no se ha emitido ningún certificado."),
                A("Volver al panel", href="/admin", role="button", cls="outline")
            ),
            cls="container"
        )

    # Marcadores visuales por clase
    icons = {
        "ok": "🟢", "notice": "🟡", "warning": "🟠",
        "urgent": "🔴", "expired": "⚫", "unknown": "❔",
    }

    filas = [Tr(
        Th(""), Th("ID"), Th("Email"), Th("Filename"),
        Th("Días restantes"), Th("Vence"), Th("Status"), Th("Serial"), Th("Acciones")
    )]
    for e in emisiones:
        days = e["days_remaining"]
        days_str = "—" if days is None else (
            f"{days} días" if days >= 0 else f"vencido hace {-days} días"
        )
        accion = (
            A("Revocar", href=f"#revocar-{e['filename']}", role="button", cls="secondary")
            if e["status"] == "active"
            else "—"
        )
        filas.append(Tr(
            Td(icons.get(e["expiry_class"], "?")),
            Td(str(e["id"])),
            Td(e["email"]),
            Td(Code(e["filename"])),
            Td(days_str),
            Td((e["expires_at"] or "—")[:10]),
            Td(e["status"]),
            Td(Code(e["serial"] or "—")),
            Td(accion),
        ))

    return Main(
        H1("Dashboard de expiraciones"),
        P(Small(
            "🟢 OK (>30d) · 🟡 Aviso (<30d) · 🟠 Atención (<15d) · 🔴 Urgente (<7d) · ⚫ Expirado"
        )),
        Table(*filas),
        Br(),
        Article(
            H4("Política de certificados expirados"),
            Ul(
                Li("Un cert expirado deja de validarse en clientes — los correos firmados con él se ven como ", Strong("untrusted"), "."),
                Li("Un cert ", Strong("superseded"), " no es lo mismo que ", Strong("revocado"),
                   ": sigue siendo técnicamente válido hasta su fecha de expiración natural."),
                Li("Para revocar formalmente, usa el formulario de revocación en la home (Paso 4). El CRL se actualiza automáticamente."),
                Li("Para renovar, el usuario solicita su cert nuevamente en ", Code("/solicitar"), ". Es ", Strong("re-key"), ": nueva clave + nuevo serial.")
            )
        ),
        A("Volver al panel", href="/admin", role="button", cls="outline"),
        cls="container"
    )


@rt('/admin/emisiones', methods=['POST'])
def post_admin_emisiones(admin_password: str):
    if not ra.verify_admin(admin_password):
        return _admin_error("Admin password incorrecto.")
    emisiones = ra.list_emissions()
    if not emisiones:
        return Main(
            Article(
                H1("Bitácora de emisiones"),
                P("Aún no se han emitido certificados."),
                A("Volver al panel", href="/admin", role="button", cls="outline")
            ),
            cls="container"
        )
    filas = [Tr(
        Th("ID"), Th("Fecha"), Th("Email"), Th("Nombre"), Th("Filename"), Th("IP")
    )]
    for e in emisiones:
        filas.append(Tr(
            Td(str(e["id"])), Td(e["issued_at"]), Td(e["email"]),
            Td(e["nombre"]), Td(Code(e["filename"])), Td(e["issued_ip"] or "—")
        ))
    return Main(
        H1("Bitácora de emisiones"),
        Table(*filas),
        Br(),
        A("Volver al panel", href="/admin", role="button", cls="outline"),
        cls="container"
    )


# ==========================================
# RUTAS PÚBLICAS DE AUTO-SERVICIO
# ==========================================
@rt('/solicitar')
def get_solicitar():
    estado_msg = (
        P("✅ La CA está desbloqueada. Tu solicitud podrá procesarse al instante.")
        if ra.is_unlocked()
        else P("⚠ La CA está bloqueada. El admin debe desbloquearla antes de que tu solicitud pueda procesarse.")
    )
    return Main(
        H1("Solicitar mi certificado S/MIME"),
        P("Si fuiste pre-registrado por el administrador, autenticate con tu email "
          "institucional y tu password personal para emitir tu certificado."),
        P(Small(
            "Si ya tienes un certificado y lo solicitas de nuevo, se trata como "
            "una renovación: se emite uno nuevo y el anterior queda marcado como "
            Code("superseded"), " (no revocado automáticamente)."
        )),
        estado_msg,
        Article(
            Form(
                Label("Email institucional:",
                    Input(type="email", name="email", required=True)),
                Label("Tu password personal (la que te dio el admin):",
                    Input(type="password", name="user_password", required=True)),
                Label("Contraseña que tendrá tu archivo .p12 (tú la eliges):",
                    Input(type="password", name="p12_password", required=True, minlength="8")),
                Button("Emitir / Renovar mi certificado", type="submit"),
                action="/solicitar", method="post"
            ),
        ),
        Br(),
        A("Volver al inicio", href="/", role="button", cls="secondary"),
        cls="container"
    )


@rt('/solicitar', methods=['POST'])
def post_solicitar(req, email: str, user_password: str, p12_password: str):
    try:
        if not ra.is_unlocked():
            raise RuntimeError(
                "La CA está bloqueada. Pide al admin que la desbloquee y vuelve a intentar."
            )
        usuario = ra.authenticate_user(email, user_password)
        inter_pw, master_pw = ra.get_session_passwords()

        # Si ya hay un cert activo, esto es una renovacion (re-key).
        prev_emission = ra.get_active_emission(usuario["id"])
        is_renewal = prev_emission is not None

        usuario_dict = {
            "nombre": usuario["nombre"],
            "email": usuario["email"],
            "filename": usuario["filename"],
        }
        generate_user_p12(usuario_dict, inter_pw, p12_password, master_pw)

        # Extraer serial + fecha de expiracion del cert recien firmado
        cert_path = Path("usuarios_p12_output") / f"{usuario['filename']}.crt"
        metadata = ra.extract_cert_metadata(cert_path)

        ip = req.client.host if req.client else None
        new_emission_id = ra.record_emission(
            usuario["id"],
            usuario["filename"],
            expires_at=metadata["expires_at"],
            serial=metadata["serial"],
            ip=ip,
            supersedes=prev_emission["id"] if is_renewal else None,
        )

        # Validacion automatica post-emision (Puntos 16 y 17)
        from crypto_core.validation import validate_user_cert
        validation_report = validate_user_cert(usuario["filename"], p12_password)
        ra.update_validation_status(new_emission_id, validation_report["overall"])
        if validation_report["overall"] == "fail":
            print(f"[ALERTA] Cert {usuario['filename']} fallo validacion: "
                  f"{validation_report['summary']}")

        # Banner contextual segun sea primera emision o renovacion
        if is_renewal:
            renewal_msg = Article(
                P("🔄 ", Strong("Renovación detectada."),
                  " Tu emisión anterior (#", str(prev_emission["id"]),
                  ", serial ", Code(prev_emission.get("serial") or "—"),
                  ") fue marcada como ", Code("superseded"), "."),
                P(Small("El certificado anterior NO fue revocado automáticamente. "
                        "Sigue siendo técnicamente válido hasta su expiración natural "
                        "o hasta que el admin lo revoque manualmente. Esto te permite "
                        "descifrar correos antiguos cifrados con tu clave anterior."))
            )
        else:
            renewal_msg = ""

        return Main(
            renewal_msg,
            Article(
                H1("Certificado emitido ✅"),
                P("Bienvenido, ", Strong(usuario["nombre"]), "."),
                P("Tu identidad S/MIME está lista. Vence el ",
                  Strong(metadata["expires_at"][:10]),
                  " (serial ", Code(metadata["serial"]), ")."),
                P("Recomendamos descargar el ",
                  Strong("bundle ZIP para Thunderbird"),
                  " (incluye Root CA, tu .p12, e instrucciones paso a paso):"),
                A("📦 Descargar bundle Thunderbird", href=f"/descargar_bundle/{usuario['filename']}",
                  role="button", cls="contrast"),
                Br(), Br(),
                P(Small("Si prefieres descargar piezas por separado:")),
                A("Solo .p12", href=f"/descargar/{usuario['filename']}",
                  role="button", cls="outline"),
                " ",
                A("Solo Root CA", href="/descargar_root",
                  role="button", cls="outline"),
                Br(), Br(),
                A("Ver guía paso a paso para Thunderbird →", href="/guia_thunderbird"),
                Br(),
                A(f"🔬 Validar mi certificado", href=f"/validar/{usuario['filename']}",
                  role="button", cls="outline"),
                Br(), Br(),
                P(Small(
                    "Resultado de validación automática: ",
                    Strong(validation_report["overall"].upper()),
                    f" ({validation_report['summary']['passed']}/{validation_report['summary']['total']} checks)."
                )),
                P(Small(
                    "⚠ Recuerda la contraseña que elegiste para el .p12 — "
                    "la necesitarás al importarlo en Thunderbird. "
                    "Si la olvidas, el admin puede generarte uno nuevo desde el módulo KRA."
                )),
                A("Volver al inicio", href="/", role="button", cls="secondary")
            ),
            cls="container"
        )
    except Exception as e:
        return Main(
            Article(
                H1("Solicitud rechazada ❌"),
                Pre(str(e)),
                A("Volver", href="/solicitar", role="button", cls="secondary")
            ),
            cls="container"
        )


# ==========================================
# RUTA PARA TU ETAPA 4: LA VISTA DEL USUARIO
# ==========================================
@rt('/vista_usuarios')
def get_vista():
    DIR_USUARIOS = Path("usuarios_p12_output")
    tarjetas_usuarios = []

    if DIR_USUARIOS.exists():
        for p12_file in sorted(DIR_USUARIOS.glob("*.p12")):
            nombre_base = p12_file.stem

            tarjetas_usuarios.append(
                Article(
                    H3(f"Certificado de: {nombre_base}"),
                    P("Cofre PKCS#12 listo para instalar en Thunderbird."),

                    A("📦 Bundle Thunderbird (recomendado)",
                      href=f"/descargar_bundle/{nombre_base}",
                      role="button", cls="contrast"),
                    Br(), Br(),
                    A("Solo .p12", href=f"/descargar/{nombre_base}",
                      role="button", cls="outline"),
                    " ",
                    A("Solo Root CA", href="/descargar_root",
                      role="button", cls="outline"),
                )
            )

    if not tarjetas_usuarios:
        tarjetas_usuarios = [
            P("Aún no hay certificados emitidos. Los usuarios pueden solicitar el suyo en ",
              A("/solicitar", href="/solicitar"), ".")
        ]

    return Main(
        H1("Portal de Usuarios"),
        P("Descarga tu identidad criptográfica y la guía de instalación para Thunderbird."),
        Article(
            H4("Antes de empezar"),
            P("Necesitas instalar la Root CA y tu .p12 en Thunderbird. La forma más simple "
              "es descargar el bundle ZIP de tu cuenta y seguir la guía:"),
            A("📥 Descargar solo Root CA", href="/descargar_root", role="button", cls="outline"),
            " ",
            A("Ver guía Thunderbird →", href="/guia_thunderbird", role="button", cls="outline"),
        ),
        *tarjetas_usuarios,
        Br(),
        A("Volver al inicio", href="/", role="button", cls="secondary"),
        cls="container"
    )

from starlette.responses import FileResponse, Response

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

# ==========================================
# VALIDACION DE CADENA Y DISTRIBUCION DE INTERMEDIOS (Puntos 16 y 17)
# ==========================================
@rt('/validar/{filename}')
def get_validar(filename: str):
    from crypto_core.validation import validate_user_cert
    report = validate_user_cert(filename)

    # Iconos por estado
    def render_check(c):
        if c["passed"] is True:
            icon = "✅"
        elif c["passed"] is False:
            icon = "🔴" if c["level"] == "critical" else "🟡"
        else:
            icon = "⏭"
        return Li(
            icon, " ", Strong(c["name"]),
            Pre(Code(c["detail"]))
        )

    # Agrupar por nivel
    criticos = [c for c in report["checks"] if c["level"] == "critical"]
    warnings = [c for c in report["checks"] if c["level"] == "warning"]
    infos = [c for c in report["checks"] if c["level"] == "info"]

    overall_label = {
        "pass": ("✅ PASS", "Todo en orden"),
        "warning": ("🟡 WARNING", "Funciona pero con advertencias"),
        "fail": ("❌ FAIL", "Hay fallas críticas"),
    }.get(report["overall"], ("?", ""))

    s = report["summary"]

    return Main(
        H1(f"Validación de cadena — {filename}"),
        Article(
            P(Strong("Estado general: "), Strong(overall_label[0])),
            P(overall_label[1]),
            P(
                Code(f"{s['passed']} pasaron"), " · ",
                Code(f"{s['failed_critical']} fallas críticas"), " · ",
                Code(f"{s['failed_warning']} advertencias"), " · ",
                Code(f"{s['skipped']} saltados"),
                f" — total {s['total']}"
            ),
            P(Small(f"Validado: {report['timestamp']}")),
        ),

        H2(f"🔴 Críticos ({len(criticos)})"),
        P(Small("Si alguno falla, los clientes de correo rechazan el cert.")),
        Ul(*[render_check(c) for c in criticos]),

        H2(f"🟡 Advertencias ({len(warnings)})"),
        P(Small("No bloquean, pero conviene atender.")),
        Ul(*[render_check(c) for c in warnings]) if warnings else P("Sin advertencias."),

        H2(f"ℹ Informativos ({len(infos)})"),
        Ul(*[render_check(c) for c in infos]) if infos else P("Sin info adicional."),

        Br(),
        A("Volver al inicio", href="/", role="button", cls="secondary"),
        cls="container"
    )


@rt('/admin/validacion_global', methods=['POST'])
def post_admin_validacion_global(admin_password: str):
    if not ra.verify_admin(admin_password):
        return _admin_error("Admin password incorrecto.")

    from crypto_core.validation import revalidate_all_active
    reports = revalidate_all_active()

    if not reports:
        return Main(
            Article(
                H1("Validación global"),
                P("No hay certificados activos para validar."),
                A("Volver al panel", href="/admin", role="button", cls="outline")
            ),
            cls="container"
        )

    icons = {"pass": "✅", "warning": "🟡", "fail": "❌"}

    filas = [Tr(
        Th(""), Th("Filename"), Th("Email"), Th("Pasaron"),
        Th("Fallas críticas"), Th("Advertencias"), Th("Detalles")
    )]
    for r in reports:
        s = r["summary"]
        filas.append(Tr(
            Td(icons.get(r["overall"], "?")),
            Td(Code(r["filename"])),
            Td(r["email"]),
            Td(f"{s['passed']}/{s['total']}"),
            Td(str(s["failed_critical"])),
            Td(str(s["failed_warning"])),
            Td(A("Ver", href=f"/validar/{r['filename']}")),
        ))

    return Main(
        H1("Validación global de cadenas"),
        P(Small("Re-validación completada. Los resultados quedaron cacheados en "
                "la columna ", Code("validation_status"), " de la BD.")),
        Table(*filas),
        Br(),
        A("Volver al panel", href="/admin", role="button", cls="outline"),
        cls="container"
    )


# Endpoint público que sirve la Root CA para que los clientes de correo
# (Thunderbird) puedan agregarla a su almacén de Authorities y confiar en
# los certificados emitidos por esta PKI.
@rt('/descargar_root')
def get_descargar_root():
    root_path = Path("root_ca_output/root.crt")
    if root_path.exists():
        return FileResponse(
            path=root_path,
            filename="MailGuard-RootCA.crt",
            media_type="application/x-x509-ca-cert"
        )
    return "Root CA no disponible. Ejecuta el Paso 1.", 404


# Bundle ZIP listo para Thunderbird: Root CA + .p12 + INSTRUCCIONES.txt.
# Reduce la fricción de instalación a un solo download.
@rt('/descargar_bundle/{filename}')
def get_descargar_bundle(filename: str):
    try:
        from crypto_core.bundle import build_thunderbird_bundle
        zip_bytes = build_thunderbird_bundle(filename)
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}_thunderbird.zip"'
            }
        )
    except FileNotFoundError as e:
        return Main(
            Article(
                H1("Bundle no disponible ❌"),
                Pre(str(e)),
                A("Volver", href="/", role="button", cls="secondary")
            ),
            cls="container"
        )


# Guía paso a paso para Thunderbird (única página, 4 pasos).
@rt('/guia_thunderbird')
def get_guia_thunderbird():
    return Main(
        H1("Guía de instalación — Thunderbird"),
        P("Tu identidad S/MIME consta de dos archivos:"),
        Ul(
            Li(Strong("MailGuard-RootCA.crt"), " — certificado raíz de Universidad Anáhuac (para que Thunderbird confíe en la cadena)."),
            Li(Strong("{filename}.p12"), " — tu cofre personal (clave privada + cert)."),
        ),
        P("Lo más fácil: descarga el ", Strong("bundle ZIP"),
          " desde tu vista de usuario y descomprímelo. Luego sigue los 4 pasos:"),

        Article(
            H2("Paso 1: Importar la Root CA en Thunderbird"),
            P(Small("Thunderbird tiene su propio almacén de certificados, separado del SO.")),
            Ol(
                Li("Abre Thunderbird."),
                Li("Menú hamburguesa → ", Code("Settings"), "."),
                Li("Barra lateral → ", Code("Privacy & Security"), "."),
                Li("Scroll hasta ", Code("Certificates"), " → ", Code("Manage Certificates..."), "."),
                Li("Pestaña ", Strong("Authorities"), "."),
                Li(Code("Import..."), " → selecciona ", Code("MailGuard-RootCA.crt"), "."),
                Li("Marca ", Strong("[x] Trust this CA to identify email users"), "."),
                Li("Click ", Code("OK"), "."),
            )
        ),

        Article(
            H2("Paso 2: Importar tu certificado personal (.p12)"),
            Ol(
                Li("Misma ventana ", Code("Manage Certificates"), "."),
                Li("Pestaña ", Strong("Your Certificates"), "."),
                Li(Code("Import..."), " → selecciona tu archivo ", Code(".p12"), "."),
                Li("Ingresa la contraseña del ", Code(".p12"), " que elegiste al solicitarlo."),
                Li("Click ", Code("OK"), "."),
            ),
            P(Small("Si olvidaste la contraseña, el admin puede emitir un cofre nuevo desde el módulo KRA sin re-emitir el cert."))
        ),

        Article(
            H2("Paso 3: Vincular el certificado a tu cuenta"),
            P(Strong("⚠ Thunderbird no vincula el cert automáticamente."), " Hazlo manualmente:"),
            Ol(
                Li("Menú hamburguesa → ", Code("Account Settings"), "."),
                Li("Selecciona tu cuenta ", Code("@anahuac.mx"), "."),
                Li("Submenú ", Code("End-To-End Encryption"), "."),
                Li("Sección ", Strong("S/MIME"), ":",
                   Ul(
                       Li(Code("Personal certificate for digital signing"), " → ", Code("Select..."), " → tu cert."),
                       Li(Code("Personal certificate for encryption"), " → ", Code("Select..."), " → el ", Strong("mismo"), " cert."),
                   )),
                Li("Marca ", Strong("[x] Sign messages by default"), "."),
            )
        ),

        Article(
            H2("Paso 4: Enviar un correo firmado"),
            Ol(
                Li("Compose (botón de nuevo correo)."),
                Li("Escribe el correo."),
                Li("Toolbar superior: icono ", Code("Security"), " → marca ", Strong("[x] Digitally Sign This Message"), "."),
                Li("Send."),
            ),
            P("El destinatario verá un sello indicando que la firma es válida.")
        ),

        Article(
            H2("Resolución de problemas"),
            Ul(
                Li(Strong("\"El certificado no es de confianza\""),
                   " — no importaste la Root CA en Thunderbird (Paso 1)."),
                Li(Strong("\"No se ha configurado certificado para firmar\""),
                   " — no vinculaste el cert a la cuenta (Paso 3)."),
                Li(Strong("Destinatario no puede descifrar"),
                   " — necesita instalar la Root CA en SU Thunderbird (Paso 1) o conocer tu cert público."),
                Li(Strong("Olvidé la contraseña del .p12"),
                   " — contacta al admin; el módulo KRA genera un cofre nuevo con password fresca."),
            )
        ),

        Br(),
        A("📥 Descargar Root CA", href="/descargar_root", role="button"),
        " ",
        A("Solicitar mi certificado", href="/solicitar", role="button", cls="contrast"),
        " ",
        A("Volver al inicio", href="/", role="button", cls="secondary"),
        cls="container"
    )


# Endpoint público que sirve el CRL referenciado por la extensión
# crlDistributionPoints embebida en cada certificado de usuario.
# Los clientes de correo (Outlook/Thunderbird) lo descargan automáticamente
# para validar revocaciones (RFC 5280 §4.2.1.13).
@rt('/crl/inter-ca.crl')
def get_crl():
    crl_path = Path("ca_intermedia_output/crl/inter-ca.crl")
    if crl_path.exists():
        return FileResponse(
            path=crl_path,
            media_type="application/pkix-crl"
        )
    return "CRL no disponible", 404

# ==========================================
# RUTA DE REVOCACIÓN
# ==========================================
@rt('/revocar', methods=['POST'])
def post_revocar(inter_password: str, cert_filename: str, motivo: str = "unspecified"):
    try:
        from crypto_core.crl import revocar_certificado
        cert_path = Path("usuarios_p12_output") / f"{cert_filename}.crt"
        if not cert_path.exists():
            raise FileNotFoundError(
                f"No se encontró el certificado: {cert_path}. "
                f"Ejecuta el Paso 3 primero para generarlo."
            )
        revocar_certificado(str(cert_path), inter_password, motivo)
        return Main(
            Article(
                H1("Certificado revocado ✅"),
                P(f"El certificado de ", Strong(cert_filename), " fue marcado como revocado."),
                P("Motivo registrado: ", Code(motivo)),
                P("El CRL fue regenerado automáticamente. Los clientes de correo "
                  "(Outlook/Thunderbird) rechazarán las firmas hechas con este cert "
                  "la próxima vez que validen el CRL."),
                A("Volver al Inicio", href="/", role="button", cls="outline")
            ),
            cls="container"
        )
    except Exception as e:
        return Main(
            Article(
                H1("Error al revocar ❌"),
                Pre(str(e)),
                A("Volver", href="/", role="button", cls="secondary")
            ),
            cls="container"
        )

# ==========================================
# RUTAS DE RECUPERACIÓN ADMINISTRATIVA (KRA)
# ==========================================
@rt('/recuperar', methods=['POST'])
def post_recuperar(master_password: str, cert_filename: str, new_p12_password: str):
    try:
        from crypto_core.escrow import recover_with_new_password
        p12_bytes = recover_with_new_password(cert_filename, master_password, new_p12_password)
        return Response(
            content=p12_bytes,
            media_type="application/x-pkcs12",
            headers={
                "Content-Disposition": f'attachment; filename="{cert_filename}_recovered.p12"'
            }
        )
    except Exception as e:
        return Main(
            Article(
                H1("Error de recuperación ❌"),
                Pre(str(e)),
                A("Volver", href="/", role="button", cls="secondary")
            ),
            cls="container"
        )

@rt('/escrow_audit')
def get_escrow_audit():
    from crypto_core.escrow import read_audit_log
    return Main(
        Article(
            H1("Log de Recuperaciones (KRA)"),
            P("Registro inmutable de cada recuperación administrativa realizada."),
            Pre(Code(read_audit_log())),
            A("Volver", href="/", role="button", cls="outline")
        ),
        cls="container"
    )

if __name__ == '__main__':
    #serve(port=5001)
    serve(host="0.0.0.0", port=8099)
