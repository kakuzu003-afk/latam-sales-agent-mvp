import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


APP_NAME = "BotBuilder LATAM"
DB_PATH = os.path.join(os.path.dirname(__file__), "botbuilder.sqlite3")
SECRETS_PATH = os.path.join(os.path.dirname(__file__), "secrets.json")


def _load_or_create_secret():
    env_secret = os.environ.get("APP_SECRET")
    if env_secret:
        return env_secret
    try:
        with open(SECRETS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("APP_SECRET"):
            return data["APP_SECRET"]
    except (OSError, json.JSONDecodeError):
        data = {}
    new_secret = secrets.token_hex(32)
    data["APP_SECRET"] = new_secret
    try:
        with open(SECRETS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass
    return new_secret


SECRET = _load_or_create_secret()


def load_local_secrets():
    if not os.path.exists(SECRETS_PATH):
        return {}
    try:
        with open(SECRETS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


LOCAL_SECRETS = load_local_secrets()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or LOCAL_SECRETS.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL") or LOCAL_SECRETS.get("GROQ_MODEL", "llama-3.3-70b-versatile")
META_WEBHOOK_TOKEN = os.environ.get("META_WEBHOOK_TOKEN") or LOCAL_SECRETS.get("META_WEBHOOK_TOKEN", "")
META_ACCESS_TOKEN = os.environ.get("META_ACCESS_TOKEN") or LOCAL_SECRETS.get("META_ACCESS_TOKEN", "")
META_API_VERSION = "v20.0"


def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                business_name TEXT NOT NULL,
                business_type TEXT,
                country_market TEXT,
                currency TEXT,
                city TEXT,
                hours TEXT,
                whatsapp TEXT,
                email TEXT,
                website TEXT,
                bot_name TEXT,
                language TEXT,
                tone TEXT,
                formality TEXT,
                knowledge TEXT,
                services TEXT,
                local_vocabulary TEXT,
                forbidden_vocabulary TEXT,
                sales_mission TEXT,
                special_instructions TEXT,
                channels TEXT,
                avoid_topics TEXT,
                groq_model TEXT,
                widget_color TEXT DEFAULT '#1d9e75',
                widget_title TEXT DEFAULT '',
                widget_welcome TEXT DEFAULT '',
                widget_label TEXT DEFAULT '',
                public_slug TEXT DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                user_id INTEGER PRIMARY KEY,
                plan TEXT NOT NULL DEFAULT 'starter',
                agent_limit INTEGER NOT NULL DEFAULT 2,
                message_limit INTEGER NOT NULL DEFAULT 300,
                status TEXT NOT NULL DEFAULT 'demo',
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS faqs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                question TEXT NOT NULL,
                answer TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                visitor_name TEXT,
                visitor_contact TEXT,
                intent TEXT,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id INTEGER NOT NULL,
                conversation_id INTEGER,
                name TEXT,
                contact TEXT,
                intent TEXT,
                status TEXT NOT NULL DEFAULT 'nuevo',
                notes TEXT DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_agents_user_updated ON agents(user_id, updated_at);
            CREATE INDEX IF NOT EXISTS idx_faqs_agent ON faqs(agent_id);
            CREATE INDEX IF NOT EXISTS idx_conversations_agent_created ON conversations(agent_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_messages_conversation_created ON messages(conversation_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_leads_agent_status_created ON leads(agent_id, status, created_at);
            CREATE INDEX IF NOT EXISTS idx_leads_conversation ON leads(conversation_id);
            """
        )
        for sql in [
            "ALTER TABLE agents ADD COLUMN widget_color TEXT DEFAULT '#1d9e75'",
            "ALTER TABLE agents ADD COLUMN widget_title TEXT DEFAULT ''",
            "ALTER TABLE agents ADD COLUMN widget_welcome TEXT DEFAULT ''",
            "ALTER TABLE agents ADD COLUMN widget_label TEXT DEFAULT ''",
            "ALTER TABLE agents ADD COLUMN public_slug TEXT DEFAULT ''",
            "ALTER TABLE leads ADD COLUMN notes TEXT DEFAULT ''",
            "ALTER TABLE agents ADD COLUMN meta_phone_id TEXT DEFAULT ''",
            "ALTER TABLE agents ADD COLUMN meta_access_token TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError:
                pass
        for agent in conn.execute("SELECT id,business_name FROM agents WHERE public_slug IS NULL OR public_slug=''").fetchall():
            conn.execute("UPDATE agents SET public_slug=? WHERE id=?", (unique_slug(conn, agent["business_name"], agent["id"]), agent["id"]))
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_slug ON agents(public_slug)")


def now():
    return int(time.time())


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    check = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(check, digest)


def sign(value):
    sig = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def unsign(value):
    if not value or "." not in value:
        return ""
    raw, sig = value.rsplit(".", 1)
    expected = hmac.new(SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return raw if hmac.compare_digest(sig, expected) else ""


def parse_form(body):
    return {k: v[0] if v else "" for k, v in urllib.parse.parse_qs(body.decode("utf-8")).items()}


def clean_message_text(text, limit=2500):
    text = str(text or "").replace("\x00", "").strip()
    return text[:limit]


def slugify(text):
    import re
    value = (text or "agente").lower()
    replacements = {"á":"a","é":"e","í":"i","ó":"o","ú":"u","ñ":"n","ü":"u"}
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value or "agente"


def unique_slug(conn, base, agent_id=None):
    base = slugify(base)
    slug = base
    i = 2
    while True:
        row = conn.execute("SELECT id FROM agents WHERE public_slug=?", (slug,)).fetchone()
        if not row or (agent_id and row["id"] == int(agent_id)):
            return slug
        slug = f"{base}-{i}"
        i += 1


def normalize_messages(messages):
    allowed = {"user", "assistant"}
    normalized = []
    for item in messages if isinstance(messages, list) else []:
        role = item.get("role") if isinstance(item, dict) else ""
        content = clean_message_text(item.get("content") if isinstance(item, dict) else "")
        if role in allowed and content:
            normalized.append({"role": role, "content": content})
    return normalized[-12:]


def json_response(handler, data, status=200):
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def redirect(handler, path):
    handler.send_response(302)
    handler.send_header("Location", path)
    handler.end_headers()


def cookie_header(name, value, max_age=None):
    c = cookies.SimpleCookie()
    c[name] = value
    c[name]["path"] = "/"
    c[name]["httponly"] = True
    c[name]["samesite"] = "Lax"
    if max_age is not None:
        c[name]["max-age"] = str(max_age)
    return c.output(header="").strip()


def get_cookie(header, name):
    if not header:
        return ""
    c = cookies.SimpleCookie()
    c.load(header)
    return c.get(name).value if c.get(name) else ""


def assistant_widget():
    return """
  <section id="platformAssistant" class="platform-assistant" aria-label="Asistente de ayuda">
    <button class="assistant-fab" type="button" onclick="togglePlatformAssistant()">Ayuda</button>
    <article class="assistant-panel" hidden>
      <header><div><strong>Asistente de la plataforma</strong><span>Te guía paso a paso</span></div><button type="button" onclick="togglePlatformAssistant()">×</button></header>
      <div id="assistantMessages" class="assistant-messages">
        <p class="bot">Hola. Puedo ayudarte a crear vendedores IA, conectar WhatsApp, entender oportunidades, revisar planes o saber qué hacer en cada pantalla.</p>
      </div>
      <div class="assistant-quick">
        <button type="button" onclick="askPlatformAssistant('¿Qué hago en esta pantalla?')">Qué hago aquí</button>
        <button type="button" onclick="askPlatformAssistant('¿Cómo creo un vendedor IA?')">Crear vendedor</button>
        <button type="button" onclick="askPlatformAssistant('¿Cómo conecto WhatsApp?')">Conectar WhatsApp</button>
      </div>
      <form onsubmit="sendPlatformAssistant(event)">
        <input id="assistantInput" placeholder="Pregunta qué hacer o cómo funciona algo...">
        <button type="submit">Enviar</button>
      </form>
    </article>
  </section>
    """


def render_page(handler, title, body, user=None, wide=False, public_nav=False):
    user_nav = ""
    if user:
        current_path = urllib.parse.urlparse(handler.path).path
        def nav_item(href, label):
            active = current_path == href or (href != "/dashboard" and current_path.startswith(href))
            return f'<a class="nav-pill {"active" if active else ""}" href="{href}">{label}</a>'
        user_nav = f"""
        {nav_item("/dashboard", "Control")}
        {nav_item("/agents/new", "Nuevo vendedor")}
        {nav_item("/inbox", "Bandeja comercial")}
        {nav_item("/leads", "Oportunidades")}
        {nav_item("/conversations", "Historial")}
        {nav_item("/billing", "Planes")}
        <a class="nav-pill logout" href="/logout">Salir</a>
        """
    elif public_nav:
        user_nav = """
        <a class="nav-pill" href="/">Inicio</a>
        <a class="nav-pill" href="/#producto">Producto</a>
        <a class="nav-pill" href="/#planes">Planes</a>
        <a class="nav-pill" href="/#contacto">Contacto</a>
        <a class="nav-pill active" href="/login">Entrar</a>
        """
    brand_href = "/dashboard" if user else "/"
    html_doc = f"""<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)} | {APP_NAME}</title>
  <style>{CSS}</style>
</head>
<body>
  <div class="bg-grid"></div>
  <header class="topbar">
    <a class="brand" href="{brand_href}">
      <span class="mark">IA</span>
      <span><strong>{APP_NAME}</strong><small>Vendedores IA para negocios de Latinoamérica</small></span>
    </a>
    <nav>{user_nav}</nav>
  </header>
  <main class="shell {'wide' if wide else ''}">
    {body}
  </main>
  {assistant_widget() if user else ''}
  <div id="toast" class="toast"></div>
  <script>{JS}</script>
</body>
</html>"""
    payload = html_doc.encode("utf-8")
    handler.send_response(200)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


SESSION_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


def current_user(handler):
    sid = unsign(get_cookie(handler.headers.get("Cookie"), "sid"))
    if not sid:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT users.*, sessions.created_at session_created FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token=?",
            (sid,),
        ).fetchone()
        if not row:
            return None
        if now() - row["session_created"] > SESSION_MAX_AGE:
            conn.execute("DELETE FROM sessions WHERE token=?", (sid,))
            return None
        return row


def require_user(handler):
    user = current_user(handler)
    if not user:
        redirect(handler, "/login")
        return None
    return user


def agent_for_user(agent_id, user_id):
    with db() as conn:
        agent = conn.execute("SELECT * FROM agents WHERE id=? AND user_id=?", (agent_id, user_id)).fetchone()
        if not agent:
            return None
        faqs = conn.execute("SELECT * FROM faqs WHERE agent_id=? ORDER BY id", (agent_id,)).fetchall()
        return agent, faqs


def public_agent(agent_id):
    with db() as conn:
        agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
        if not agent:
            return None
        faqs = conn.execute("SELECT * FROM faqs WHERE agent_id=? ORDER BY id", (agent_id,)).fetchall()
        return agent, faqs


def public_agent_by_slug(slug):
    with db() as conn:
        agent = conn.execute("SELECT * FROM agents WHERE public_slug=?", (slug,)).fetchone()
        if not agent:
            return None
        faqs = conn.execute("SELECT * FROM faqs WHERE agent_id=? ORDER BY id", (agent["id"],)).fetchall()
        return agent, faqs


def ensure_subscription(user_id):
    with db() as conn:
        sub = conn.execute("SELECT * FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
        if not sub:
            conn.execute(
                "INSERT INTO subscriptions (user_id,plan,agent_limit,message_limit,status,created_at) VALUES (?,?,?,?,?,?)",
                (user_id, "starter", 2, 300, "demo", now()),
            )
            sub = conn.execute("SELECT * FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
        return sub


def quality_score(agent, faqs):
    score = 0
    checks = []
    rules = [
        ("Información del negocio completa", len(agent["knowledge"] or "") >= 350, 24),
        ("WhatsApp conectado", bool(agent["whatsapp"]), 12),
        ("Misión comercial definida", len(agent["sales_mission"] or "") >= 80, 16),
        ("País/mercado definido", bool(agent["country_market"]), 10),
        ("Servicios claros", len(agent["services"] or "") >= 80, 12),
        ("Preguntas frecuentes cargadas", len(faqs) >= 2, 14),
        ("Límites y estilo definidos", bool(agent["forbidden_vocabulary"] or agent["avoid_topics"]), 12),
    ]
    for label, ok, points in rules:
        if ok:
            score += points
        checks.append((label, ok))
    return min(score, 100), checks


def quality_recommendations(agent, faqs):
    if not agent:
        return ["Completa los datos del negocio para medir la calidad del vendedor IA."]
    recs = []
    if len(agent["knowledge"] or "") < 350:
        recs.append("Agrega una descripcion mas completa: precios, condiciones, pasos de venta, garantias y limites.")
    if len(agent["services"] or "") < 80:
        recs.append("Detalla productos o servicios con rangos de precio, duracion, zonas o requisitos.")
    if len(agent["sales_mission"] or "") < 80:
        recs.append("Define el objetivo comercial: vender, agendar, cotizar, filtrar o derivar.")
    if not agent["whatsapp"]:
        recs.append("Carga WhatsApp para que el vendedor IA pueda derivar oportunidades reales.")
    if len(faqs) < 2:
        recs.append("Agrega al menos dos FAQs con dudas reales de clientes.")
    if not (agent["forbidden_vocabulary"] or agent["avoid_topics"]):
        recs.append("Define limites: que no debe prometer, inventar o responder.")
    return recs or ["El vendedor IA está listo para probar con clientes reales. Revisa conversaciones y ajusta con datos del negocio."]


def agent_status(agent, faqs):
    score, _ = quality_score(agent, faqs)
    if score >= 80 and agent["whatsapp"] and agent["knowledge"]:
        return "listo para WhatsApp", "ready"
    if score >= 55:
        return "activo, falta pulir", "active"
    return "falta configurar", "draft"


def improve_knowledge_text(config):
    current = (config.get("knowledge") or "").strip()
    missing = []
    if len(current) < 300:
        missing.append("más contexto sobre cómo vende y atiende el negocio")
    for key, label in [
        ("services", "servicios/productos con condiciones"),
        ("sales_mission", "objetivo comercial del vendedor IA"),
        ("whatsapp", "canal de derivación"),
        ("country_market", "país o forma local de hablar"),
    ]:
        if not (config.get(key) or "").strip():
            missing.append(label)
    if GROQ_API_KEY:
        prompt = f"""Mejora esta base de conocimiento para un vendedor IA latinoamericano.
Devuelve JSON estricto con: missing, suggestions, questions, improved.
No inventes datos concretos; marca supuestos como pendientes.

DATOS:
{json.dumps(config, ensure_ascii=False, indent=2)}
"""
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=json.dumps({
                "model": config.get("groq_model") or GROQ_MODEL,
                "temperature": 0.25,
                "max_completion_tokens": 900,
                "messages": [
                    {"role": "system", "content": "Eres consultor experto en vendedores IA para negocios latinoamericanos. Respondes solo JSON válido."},
                    {"role": "user", "content": prompt},
                ],
            }).encode("utf-8"),
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=35) as res:
                text = json.loads(res.read().decode("utf-8"))["choices"][0]["message"]["content"]
                import re as _re
                cleaned = _re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
                return json.loads(cleaned)
        except Exception:
            pass
    questions = [
        "¿Cuáles son los precios, rangos o condiciones que sí puede mencionar?",
        "¿Cuándo debe derivar a una persona por WhatsApp?",
        "¿Qué objeciones frecuentes hacen los clientes antes de comprar?",
        "¿Qué datos debe pedir para cotizar, reservar o agendar?",
    ]
    improved = current or "Describe aquí cómo funciona el negocio y cómo debe vender el vendedor IA."
    improved += "\n\nEl vendedor IA debe actuar como asistente comercial humano: entender la necesidad, responder con información real, hacer preguntas de seguimiento y derivar a WhatsApp cuando el cliente quiera comprar, reservar, cotizar o hablar con una persona."
    if config.get("services"):
        improved += f"\n\nServicios/productos principales: {config.get('services')}"
    if config.get("sales_mission"):
        improved += f"\n\nMisión comercial: {config.get('sales_mission')}"
    if config.get("country_market"):
        improved += f"\n\nDebe adaptarse con respeto al mercado de {config.get('country_market')}, sin exagerar modismos."
    return {
        "missing": missing or ["La base se ve razonable; agrega precios, garantías y objeciones si existen."],
        "suggestions": [
            "Separar servicios, límites y pasos de venta.",
            "Agregar qué datos pedir antes de derivar.",
            "Definir qué no debe prometer el vendedor IA.",
        ],
        "questions": questions,
        "improved": improved,
    }


def tone_behavior(tone):
    return {
        "amigable y cercano": "Usa frases cálidas, simples y naturales. Haz que el cliente sienta que está hablando con alguien disponible y fácil de tratar.",
        "profesional y confiable": "Responde con estructura, claridad y seguridad. Evita adornos innecesarios y enfoca la conversación en resolver y avanzar.",
        "formal y respetuoso": "Mantén distancia profesional, vocabulario sobrio y trato cuidadoso. Evita bromas, exceso de cercanía o expresiones demasiado informales.",
        "juvenil y dinámico": "Usa energía, frases breves y ritmo ágil. Puedes sonar moderno, pero sin exagerar emojis ni perder claridad comercial.",
        "técnico y preciso": "Prioriza exactitud, detalles útiles, condiciones y pasos concretos. Evita respuestas vagas y explica cuando falten datos.",
        "empático y paciente": "Reconoce la necesidad del cliente, responde con calma y acompaña el proceso. Ideal para dudas sensibles o clientes indecisos.",
    }.get(tone or "", "Usa frases cálidas, simples y naturales.")


def build_prompt(agent, faqs):
    faq_text = "\n".join([f"{i+1}. Pregunta: {f['question']}\n   Respuesta: {f['answer']}" for i, f in enumerate(faqs)])
    return f"""Eres {agent['bot_name'] or 'el asistente'}, agente comercial de IA de {agent['business_name']}.

REGLA PRINCIPAL
La Base de conocimiento principal es la fuente más importante. Los otros campos son referencias de apoyo. Si hay conflicto, prioriza la Base de conocimiento principal. No inventes datos.

IDENTIDAD HUMANA DEL AGENTE
No actúes como un chatbot genérico. Actúa como un asistente comercial humano, capacitado, respetuoso y atento. Tu trabajo es ayudar al cliente a avanzar: entender lo que necesita, responder con información real del negocio, resolver dudas, manejar objeciones con honestidad y derivar a una persona cuando sea necesario.

OBJETIVO COMERCIAL
{agent['sales_mission'] or 'Entender la necesidad del cliente, responder bien y llevarlo al siguiente paso.'}

NEGOCIO
- Tipo: {agent['business_type'] or 'No especificado'}
- Ubicación: {agent['city'] or 'No especificada'}
- Base de conocimiento principal: {agent['knowledge'] or 'No especificada'}
- Productos o servicios: {agent['services'] or 'No especificados'}
- Horario: {agent['hours'] or 'No especificado'}

IDIOMA, CULTURA Y TRATO
- Tono: {agent['tone'] or 'amigable y cercano'}
- Cómo aplicar el tono: {tone_behavior(agent['tone'])}
- Idioma: {agent['language'] or 'Español'}
- País o mercado principal: {agent['country_market'] or 'Latinoamérica general'}
- Moneda de referencia: {agent['currency'] or 'No especificada'}
- Nivel de formalidad: {agent['formality'] or 'cercano y respetuoso'}
- Palabras, costumbres o formas locales permitidas: {agent['local_vocabulary'] or 'Usar español latinoamericano claro, natural y respetuoso.'}
- Palabras o estilos que debe evitar: {agent['forbidden_vocabulary'] or 'Evitar sonar robótico, exagerar modismos, inventar datos o presionar al cliente.'}
- Instrucciones especiales: {agent['special_instructions'] or 'Sin instrucciones adicionales.'}

CONTACTO
- WhatsApp: {agent['whatsapp'] or 'No especificado'}
- Email: {agent['email'] or 'No especificado'}
- Sitio web: {agent['website'] or 'No especificado'}
- Canales: {agent['channels'] or 'WhatsApp'}

PREGUNTAS FRECUENTES
{faq_text or 'No hay preguntas frecuentes cargadas.'}

TEMAS A EVITAR
{agent['avoid_topics'] or 'No hay temas restringidos.'}

COMPORTAMIENTO EN CADA RESPUESTA
- Lee la intención del cliente antes de responder.
- Responde como una persona que trabaja bien: breve, útil, amable y segura.
- Haz una pregunta de seguimiento cuando falte información para vender, cotizar o agendar.
- Si el cliente muestra intención de compra, reserva o cotización, guíalo al siguiente paso.
- Si falta información, dilo con honestidad y ofrece derivar.
- No digas "soy un bot" salvo que el cliente lo pregunte directamente.
- Si el cliente entrega nombre, teléfono, email, WhatsApp o intención clara de compra/reserva, pide permiso para derivarlo.

FLUJO COMERCIAL
1. Entiende la necesidad real antes de ofrecer.
2. Responde con datos del negocio y evita inventar.
3. Maneja objeciones con honestidad: precio, confianza, tiempo, disponibilidad o dudas.
4. Cierra con un siguiente paso concreto: reservar, cotizar, enviar datos, visitar, pagar o hablar por WhatsApp.

REGLAS PARA LATAM
- Adapta el idioma al país indicado, pero sin exagerar modismos.
- Usa respeto y calidez incluso si el cliente esta molesto.
- Si el cliente parece apurado, responde corto y ofrece WhatsApp.
- Si el cliente esta indeciso, pregunta contexto y recomienda la opcion mas segura con los datos disponibles.
"""


def call_groq(agent, faqs, messages):
    if not GROQ_API_KEY:
        return demo_reply(agent, messages[-1]["content"] if messages else "")
    safe_messages = normalize_messages(messages)
    payload = {
        "model": agent["groq_model"] or GROQ_MODEL,
        "temperature": 0.35,
        "max_completion_tokens": 700,
        "messages": [{"role": "system", "content": build_prompt(agent, faqs)}] + safe_messages,
    }
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=35) as res:
            data = json.loads(res.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except (urllib.error.URLError, KeyError, IndexError, json.JSONDecodeError):
        return demo_reply(agent, safe_messages[-1]["content"] if safe_messages else "")


def demo_reply(agent, text):
    lower = (text or "").lower()
    bot = agent["bot_name"] or "el asistente"
    tone = (agent["tone"] or "").lower()

    def _warm(msg):
        if "juvenil" in tone:
            return msg.replace("Claro,", "¡Dale,").replace("Perfecto,", "¡Genial,")
        if "formal" in tone:
            return msg.replace("Claro,", "Con gusto,").replace("Perfecto,", "Entendido,")
        if "técnico" in tone or "profesional" in tone:
            return msg.replace("Claro,", "De acuerdo,").replace("Perfecto,", "Correcto,")
        return msg

    if "precio" in lower or "cotiz" in lower:
        details = (agent["services"] or agent["knowledge"] or "").strip()
        if len(details) > 220:
            details = details[:220].rsplit(" ", 1)[0] + "..."
        detail_text = f" Según lo que tenemos cargado: {details.rstrip('.')}." if details else ""
        return _warm(f"Claro, te ayudo a cotizar.{detail_text} Para avanzar bien, dime qué servicio necesitas, para qué día u horario y tu nombre. Si quieres confirmar disponibilidad ahora, te derivo al WhatsApp {agent['whatsapp'] or 'del negocio'}.")
    if "horario" in lower:
        return _warm(f"Atendemos en este horario: {agent['hours'] or 'aún no se cargó el horario exacto'}. ¿Quieres que te ayude a agendar o consultar disponibilidad?")
    if "whatsapp" in lower or "hablar" in lower:
        return _warm(f"Claro. Puedes escribir por WhatsApp a {agent['whatsapp'] or 'el número que configure el negocio'}. Antes de derivarte, dime tu nombre y qué necesitas para que te atiendan mejor.")
    if "servicio" in lower or "producto" in lower:
        return _warm(f"Los servicios principales son: {agent['services'] or 'aún no se cargó la lista de servicios'}. Si me dices qué estás buscando, puedo recomendarte el siguiente paso.")
    if "agendar" in lower or "reserv" in lower or "hora" in lower:
        return _warm(f"Perfecto, puedo ayudarte a coordinar. Dime tu nombre, servicio que necesitas, día y horario ideal. Luego lo confirmamos por WhatsApp {agent['whatsapp'] or 'del negocio'}.")
    if any(w in lower for w in ["molesto", "queja", "reclamo", "enojado"]):
        if "empático" in tone:
            return f"Entiendo tu molestia y me apena que hayas tenido esa experiencia. Cuéntame qué pasó y busco la mejor forma de ayudarte."
        return _warm(f"Entiendo. Lamento lo ocurrido. Cuéntame el detalle y lo gestiono para que te atiendan bien.")
    return _warm(f"Entiendo. Soy {bot} de {agent['business_name']}. Puedo orientarte y ayudarte a avanzar con una cotización, reserva o contacto. ¿Qué necesitas resolver hoy?")


def detect_lead(text):
    lower = (text or "").lower()
    has_contact = any(x in lower for x in ["@", "+", "whatsapp", "fono", "teléfono", "telefono"]) or any(ch.isdigit() for ch in lower)
    intent_words = ["comprar", "precio", "cotizar", "agendar", "reservar", "quiero", "me interesa", "hablar"]
    has_intent = any(w in lower for w in intent_words)
    return has_contact or has_intent


def lead_status_from_intent(intent):
    lowered = (intent or "").lower()
    if "cotiz" in lowered or "precio" in lowered:
        return "cotizacion"
    if "agenda" in lowered or "reserva" in lowered:
        return "agendado"
    if "compra" in lowered or "interés" in lowered or "interes" in lowered:
        return "interesado"
    return "nuevo"


def upsert_lead(conn, agent_id, conv_id, name, contact, intent, notes):
    existing = conn.execute(
        "SELECT id, notes FROM leads WHERE agent_id=? AND conversation_id=? AND status IN ('nuevo','interesado','cotizacion','agendado','contactado') ORDER BY id DESC LIMIT 1",
        (agent_id, conv_id),
    ).fetchone()
    if existing:
        merged_notes = notes if notes in (existing["notes"] or "") else ((existing["notes"] or "") + "\n" + notes).strip()
        conn.execute(
            "UPDATE leads SET name=COALESCE(NULLIF(?,''), name), contact=COALESCE(NULLIF(?,''), contact), intent=?, notes=? WHERE id=?",
            (name or "", contact or "", intent, merged_notes, existing["id"]),
        )
        return False
    conn.execute(
        "INSERT INTO leads (agent_id,conversation_id,name,contact,intent,status,notes,created_at) VALUES (?,?,?,?,?,?,?,?)",
        (agent_id, conv_id, name or "", contact or "", intent or "consulta", lead_status_from_intent(intent), notes or "", now()),
    )
    return True


def extract_contact(text):
    text = text or ""
    email = re_search(r"[\w\.-]+@[\w\.-]+\.\w+", text)
    if email:
        return email
    phone = re_search(r"(\+?\d[\d\s\-\(\)]{7,}\d)", text)
    return phone or ""


def infer_intent(text):
    lower = (text or "").lower()
    checks = [
        ("reclamo", ["molesto", "reclamo", "queja", "nadie me respondió", "mala atención"]),
        ("Precio / cotización", ["precio", "cuánto", "cuanto", "cotizar", "cotización", "valor"]),
        ("Agenda / reserva", ["agendar", "reservar", "hora", "cita", "disponibilidad"]),
        ("Derivar a WhatsApp", ["whatsapp", "hablar", "contactar", "llamar"]),
        ("Compra / interés alto", ["comprar", "me interesa", "quiero contratar", "lo quiero"]),
        ("soporte", ["problema", "ayuda", "no funciona", "soporte"]),
    ]
    for label, words in checks:
        if any(w in lower for w in words):
            return label
    return "consulta"


def conversation_priority(text, contact=""):
    lowered = (text or "").lower()
    if contact or any(w in lowered for w in ["comprar", "agendar", "reservar", "cotizar", "precio", "whatsapp", "me interesa"]):
        return "Alta", "hot"
    if any(w in lowered for w in ["duda", "consulta", "información", "informacion", "horario", "servicio"]):
        return "Media", "warm"
    return "Baja", "cold"


def next_action_for_intent(intent, contact=""):
    lowered = (intent or "").lower()
    if "precio" in lowered or "cotiz" in lowered:
        return "Enviar cotización o confirmar rango por WhatsApp."
    if "agenda" in lowered or "reserva" in lowered:
        return "Confirmar disponibilidad y dejar la reserva tomada."
    if "whatsapp" in lowered:
        return "Responder por WhatsApp con contexto de la consulta."
    if "compra" in lowered or "interés" in lowered or "interes" in lowered:
        return "Contactar rápido y cerrar siguiente paso."
    if contact:
        return "Hacer seguimiento porque ya dejó contacto."
    return "Revisar si falta información para calificar mejor."


PLATFORM_GUIDE = """
Eres el asistente interno de BotBuilder LATAM. Ayudas a clientes no tecnicos a usar la plataforma.
Habla siempre en español claro, breve y amable. No menciones proveedores, modelos ni detalles tecnicos.

Funciones disponibles para el cliente:
- Control: muestra vendedores activos, calidad, oportunidades, conversaciones, embudo y actividad.
- Nuevo vendedor: crea o edita un vendedor IA con negocio, informacion principal, cultura, venta, WhatsApp y prueba final.
- Bandeja comercial: permite revisar conversaciones, prioridad, contacto detectado y siguiente accion sugerida.
- Oportunidades: muestra clientes detectados por interes, precio, agenda, compra o WhatsApp. Permite cambiar estado y guardar notas.
- Historial: muestra conversaciones del negocio con intencion, prioridad y accion recomendada.
- Planes: permite elegir Inicial, Crecimiento o Agencia. Cambiar plan mantiene los datos.
- WhatsApp: es el canal principal por ahora. El cliente carga su numero y el sistema lo usa para derivar oportunidades reales.
- Boton web: queda como opcion secundaria. Sirve para mostrar el vendedor en una pagina web cuando el negocio ya tenga sitio.

Reglas:
- Si el cliente pregunta "que hago aqui", explica la pantalla actual segun la ruta.
- Si no sabe el paso siguiente, recomienda una accion concreta.
- Si falta informacion para vender mejor, sugiere agregar precios, horarios, zonas, garantias, formas de pago, limites y preguntas frecuentes.
"""


def route_help(path):
    if path.startswith("/agents/") or path == "/agents/new":
        return "En esta pantalla configuras el vendedor IA. Empieza por la informacion del negocio, luego cultura y trato, despues venta, WhatsApp y prueba final."
    if path.startswith("/leads"):
        return "En Oportunidades ves clientes detectados. Cambia el estado, guarda notas y usa WhatsApp para hacer seguimiento."
    if path.startswith("/inbox"):
        return "En la Bandeja comercial atiendes conversaciones: revisa prioridad, contacto y siguiente accion sugerida."
    if path.startswith("/conversations"):
        return "En Historial revisas conversaciones pasadas para entender que pidio cada cliente y mejorar el seguimiento."
    if path.startswith("/billing"):
        return "En Planes eliges cuanta capacidad necesita el negocio. Cambiar de plan mantiene vendedores, oportunidades y conversaciones."
    if path.startswith("/chat"):
        return "En la prueba del vendedor simulas clientes reales y revisas si deriva bien a WhatsApp. El boton web es opcional para negocios que ya tienen pagina."
    return "En Control ves el estado general del negocio: vendedores, oportunidades, conversaciones, calidad y ventas ganadas."


def local_platform_help(message, path):
    text = (message or "").lower()
    screen = route_help(path)
    if any(w in text for w in ["esta pantalla", "aqui", "aquí", "donde estoy"]):
        return screen
    if any(w in text for w in ["crear", "vendedor", "agente"]):
        return "Para crear un vendedor IA entra a Nuevo vendedor, completa la informacion del negocio, agrega productos o servicios, define como debe vender, carga el WhatsApp y guarda. Luego prueba si responde y deriva bien."
    if any(w in text for w in ["whatsapp", "conectar", "contacto", "derivar"]):
        return "Por ahora WhatsApp es el canal principal. Carga el numero del negocio con codigo de pais. Cuando un cliente pida precio, agenda, compra o contacto, el vendedor IA debe pedir contexto y llevarlo a WhatsApp."
    if any(w in text for w in ["boton", "botón", "instalar", "web", "codigo", "código"]):
        return "El boton web es opcional. Sirve si el negocio tiene pagina web y quiere mostrar un boton de atencion. Para este MVP, lo importante es conectar WhatsApp y probar que el vendedor derive bien."
    if any(w in text for w in ["oportunidad", "cliente", "lead"]):
        return "Las oportunidades aparecen cuando una persona pide precio, agenda, compra o deja contacto. Desde ahi puedes cambiar el estado, guardar notas y responder por WhatsApp."
    if any(w in text for w in ["plan", "pago", "precio", "mensajes"]):
        return "En Planes puedes pasar de Inicial a Crecimiento o Agencia. El cambio conserva tus vendedores, conversaciones y oportunidades. Para cambio automatico al pagar falta conectar una pasarela de pago."
    if any(w in text for w in ["mejorar", "calidad", "vender"]):
        return "Para que venda mejor, agrega precios o rangos, horarios, zonas de atencion, formas de pago, garantias, objeciones frecuentes y cuando debe derivar a WhatsApp."
    return f"{screen} Si quieres, dime que intentas lograr y te indico el siguiente paso."


def platform_destination(message, path):
    text = (message or "").lower()
    explicit = any(w in text for w in ["llevar", "llevame", "llévame", "ir a", "abrir", "mandame", "mándame", "quiero ir", "vamos a"])
    options = [
        ("/agents/new", "Ir a crear vendedor", ["crear vendedor", "nuevo vendedor", "crear agente", "configurar vendedor", "hacer vendedor"]),
        ("/leads", "Ir a oportunidades", ["oportunidad", "oportunidades", "cliente interesado", "clientes interesados", "lead", "leads", "seguimiento"]),
        ("/inbox", "Ir a bandeja comercial", ["bandeja", "atender", "responder cliente", "crm", "comercial"]),
        ("/conversations", "Ir al historial", ["historial", "conversaciones", "conversacion", "mensajes"]),
        ("/billing", "Ir a planes", ["plan", "planes", "pago", "pagar", "precio", "mensajes disponibles", "crecimiento"]),
        ("/dashboard", "Ir a control", ["panel", "control", "dashboard", "inicio", "resumen"]),
    ]
    for url, label, words in options:
        if any(w in text for w in words):
            return {"url": url, "label": label, "navigate": explicit}
    if any(w in text for w in ["whatsapp", "conectar whatsapp", "numero", "número", "derivar"]):
        return {"url": "/agents/new", "label": "Configurar WhatsApp", "navigate": explicit}
    if any(w in text for w in ["instalar", "boton", "botón", "web", "codigo", "código", "probar"]):
        if path.startswith("/agents/") and path.endswith("/edit"):
            try:
                agent_id = path.split("/")[2]
                return {"url": f"/chat/{agent_id}", "label": "Ir a prueba del vendedor", "navigate": explicit}
            except IndexError:
                pass
        return {"url": "/agents/new", "label": "Configurar WhatsApp primero", "navigate": explicit}
    return None


def platform_help_reply(message, path):
    fallback = local_platform_help(message, path)
    if not GROQ_API_KEY:
        return fallback
    payload = {
        "model": GROQ_MODEL,
        "temperature": 0.25,
        "max_completion_tokens": 420,
        "messages": [
            {"role": "system", "content": PLATFORM_GUIDE},
            {"role": "user", "content": f"Ruta actual: {path}\nPregunta del cliente: {clean_message_text(message, 1200)}"},
        ],
    }
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as res:
            data = json.loads(res.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return fallback


def re_search(pattern, text):
    import re
    match = re.search(pattern, text)
    return match.group(0).strip() if match else ""


def get_base_url(handler):
    """Returns the base URL for the current request (respects APP_URL env var for production)."""
    app_url = os.environ.get("APP_URL", "").rstrip("/")
    if app_url:
        return app_url
    host = handler.headers.get("Host", "localhost:8765")
    is_local = "localhost" in host or "127.0.0.1" in host
    scheme = "http" if is_local else "https"
    return f"{scheme}://{host}"


def send_whatsapp_message(phone_number_id, access_token, to, text):
    """Sends a text message via the Meta WhatsApp Business API."""
    token = access_token or META_ACCESS_TOKEN
    if not token or not phone_number_id:
        return False
    payload = json.dumps({
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to,
        "type": "text",
        "text": {"preview_url": False, "body": text[:4096]},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"https://graph.facebook.com/{META_API_VERSION}/{phone_number_id}/messages",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            return res.status == 200
    except urllib.error.URLError:
        return False


def get_or_create_whatsapp_conversation(conn, agent_id, sender_phone):
    """Returns (conv_id, history) for a WhatsApp sender, creating one if needed."""
    row = conn.execute(
        "SELECT id FROM conversations WHERE agent_id=? AND visitor_contact=? ORDER BY id DESC LIMIT 1",
        (agent_id, sender_phone),
    ).fetchone()
    if row:
        conv_id = row["id"]
    else:
        cur = conn.execute(
            "INSERT INTO conversations (agent_id, visitor_contact, created_at) VALUES (?,?,?)",
            (agent_id, sender_phone, now()),
        )
        conv_id = cur.lastrowid
    msgs = conn.execute(
        "SELECT role, content FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 12",
        (conv_id,),
    ).fetchall()
    history = [{"role": m["role"], "content": m["content"]} for m in reversed(msgs)]
    return conv_id, history


class App(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/widget.js":
            self.serve_widget_js()
        elif path.startswith("/widget/") and path.endswith(".js"):
            self.serve_public_widget_js(path.split("/")[2][:-3])
        elif path == "/webhook/whatsapp":
            self.webhook_whatsapp_verify()
        elif path.startswith("/l/"):
            self.page_link_bio(path.split("/")[2])
        elif path.startswith("/a/"):
            self.page_public_agent(path.split("/")[2])
        elif path == "/":
            self.page_home()
        elif path == "/privacidad":
            self.page_legal("Política de privacidad")
        elif path == "/politica-privacidad":
            self.page_privacy_policy()
        elif path == "/terminos":
            self.page_legal("Términos de servicio")
        elif path == "/soporte":
            self.page_legal("Soporte")
        elif path == "/login":
            self.page_login()
        elif path == "/logout":
            self.logout()
        elif path == "/dashboard":
            user = require_user(self)
            if user:
                self.page_dashboard(user)
        elif path == "/agents/new":
            user = require_user(self)
            if user:
                self.page_agent_form(user)
        elif path.startswith("/agents/") and path.endswith("/edit"):
            user = require_user(self)
            if user:
                try:
                    agent_id = int(path.split("/")[2])
                except (ValueError, IndexError):
                    self.send_error(404)
                    return
                self.page_agent_form(user, agent_id)
        elif path.startswith("/chat/"):
            try:
                agent_id = int(path.split("/")[2])
            except (ValueError, IndexError):
                self.send_error(404)
                return
            self.page_chat(agent_id)
        elif path == "/leads":
            user = require_user(self)
            if user:
                self.page_leads(user)
        elif path == "/inbox":
            user = require_user(self)
            if user:
                self.page_inbox(user)
        elif path == "/billing":
            user = require_user(self)
            if user:
                self.page_billing(user)
        elif path == "/conversations":
            user = require_user(self)
            if user:
                self.page_conversations(user)
        elif path.startswith("/conversations/"):
            user = require_user(self)
            if user:
                try:
                    conv_id = int(path.split("/")[2])
                except (ValueError, IndexError):
                    self.send_error(404)
                    return
                self.page_conversation_detail(user, conv_id)
        else:
            self.send_error(404)

    def page_home(self):
        body = """
        <section class="landing-hero">
          <div class="landing-copy">
            <p class="eyebrow">Plataforma comercial para LATAM</p>
            <h1>Vendedores IA para WhatsApp e Instagram.</h1>
            <p>Entrena asistentes comerciales con información real del negocio, prueba conversaciones y convierte consultas en oportunidades listas para seguimiento.</p>
            <div class="actions">
              <a class="btn primary big-cta" href="/login">Entrar al panel</a>
              <a class="btn" href="#producto">Ver plataforma</a>
            </div>
            <div class="landing-metrics">
              <article><strong>24/7</strong><span>Atención inicial</span></article>
              <article><strong>LATAM</strong><span>Tono y cultura</span></article>
              <article><strong>IA + CRM</strong><span>Venta y seguimiento</span></article>
            </div>
          </div>
          <div class="landing-console">
            <div class="console-bar"><span></span><strong>Centro de control</strong><em>activo</em></div>
            <div class="console-stats">
              <article><strong>18</strong><span>Oportunidades</span></article>
              <article><strong>71%</strong><span>Calidad</span></article>
              <article><strong>5</strong><span>Ventas listas</span></article>
            </div>
            <div class="console-feed">
              <div><b>Studio Corte</b><span>Cliente pidió precio y horario por WhatsApp</span></div>
              <div><b>Aura Clínica</b><span>Interesada en evaluación estética</span></div>
              <div><b>Urban Market</b><span>Consulta por talla, envío y garantía</span></div>
            </div>
          </div>
        </section>

        <section id="producto" class="landing-section">
          <p class="eyebrow">Producto</p>
          <h2>Todo lo necesario para crear, probar y operar vendedores IA.</h2>
          <div class="infra-map">
            <div class="infra-core">
              <span>IA</span>
              <strong>Motor comercial</strong>
              <small>Entrenamiento + conversación + seguimiento</small>
            </div>
            <article class="infra-node n1"><span>01</span><strong>Conocimiento</strong><p>Servicios, precios, horarios y reglas reales del negocio.</p></article>
            <article class="infra-node n2"><span>02</span><strong>Canales</strong><p>WhatsApp, Instagram y link comercial preparados para captar consultas.</p></article>
            <article class="infra-node n3"><span>03</span><strong>Prueba</strong><p>Escenarios de venta antes de publicar o conectar canales oficiales.</p></article>
            <article class="infra-node n4"><span>04</span><strong>Oportunidades</strong><p>Intención, contacto, prioridad y próximo paso comercial.</p></article>
          </div>
        </section>

        <section class="landing-section channels-band">
          <div>
            <p class="eyebrow">Canales</p>
            <h2>Diseñado para los canales donde se cierran ventas.</h2>
            <p>El producto prioriza WhatsApp e Instagram. La plataforma ya organiza vendedores, conversaciones, oportunidades y estados para avanzar hacia conexión oficial con Meta.</p>
          </div>
          <div class="channel-cards">
            <article><span>WhatsApp</span><strong>Cierre y seguimiento</strong><p>Ideal para reservas, cotizaciones, confirmaciones y ventas.</p></article>
            <article><span>Instagram</span><strong>Entrada de clientes</strong><p>Perfecto para perfiles, anuncios, historias y mensajes directos.</p></article>
          </div>
        </section>

        <section id="planes" class="landing-section">
          <p class="eyebrow">Modelo comercial</p>
          <h2>Planes pensados para vender por negocio o por agencia.</h2>
          <div class="pricing-grid">
            <article class="pricing-card"><span>Inicial</span><h3>Para validar</h3><strong>$19<small>/mes</small></strong><p>Link comercial, vendedor IA y oportunidades.</p></article>
            <article class="pricing-card active"><span>Recomendado</span><h3>Crecimiento</h3><strong>$49<small>/mes</small></strong><p>Más vendedores, más mensajes y panel comercial.</p></article>
            <article class="pricing-card"><span>Agencia</span><h3>Para varios clientes</h3><strong>$149<small>/mes</small></strong><p>Gestión multi-negocio y capacidad ampliada.</p></article>
          </div>
        </section>

        <section id="contacto" class="landing-section contact-band">
          <div>
            <p class="eyebrow">Empezar</p>
            <h2>Empieza con un vendedor IA entrenado y una operación comercial clara.</h2>
            <p>Usa el panel para configurar, probar, compartir y medir oportunidades. Luego conecta canales oficiales cuando el negocio esté listo.</p>
          </div>
          <div class="actions"><a class="btn primary big-cta" href="/login">Entrar a la plataforma</a><a class="btn" href="/soporte">Soporte</a></div>
        </section>

        <footer class="landing-footer">
          <a href="/privacidad">Privacidad</a>
          <a href="/terminos">Términos</a>
          <a href="/soporte">Soporte</a>
        </footer>
        """
        render_page(self, "Vendedores IA para WhatsApp e Instagram", body, None, wide=True, public_nav=True)

    def page_legal(self, title):
        content = {
            "Política de privacidad": ("Privacidad", "Protegemos los datos de negocios, clientes y conversaciones. La información cargada se usa para configurar vendedores IA, responder consultas, detectar oportunidades y mejorar el servicio. No pedimos contraseñas personales de redes sociales; las conexiones oficiales se realizan por autorización segura."),
            "Términos de servicio": ("Términos", "BotBuilder LATAM entrega herramientas para crear vendedores IA, capturar oportunidades y conectar canales comerciales. El cliente es responsable de cargar información real del negocio, respetar normas de comunicación y usar los canales de forma legítima."),
            "Soporte": ("Soporte", "Para ayuda con configuración, vendedores IA, oportunidades, WhatsApp, Instagram o planes, contáctanos desde la plataforma o solicita acompañamiento de activación.")
        }.get(title, ("Información", "Página informativa."))
        body = f"""
        <section class="legal-page">
          <p class="eyebrow">{esc(content[0])}</p>
          <h1>{esc(title)}</h1>
          <p>{esc(content[1])}</p>
          <div class="actions"><a class="btn primary" href="/">Volver al inicio</a><a class="btn" href="/login">Entrar</a></div>
        </section>
        """
        render_page(self, title, body, None, wide=False, public_nav=True)

    def page_privacy_policy(self):
        """Política de privacidad para Meta y usuarios."""
        body = """
        <section class="legal-page">
          <p class="eyebrow">Privacidad</p>
          <h1>Política de Privacidad</h1>
          <p><strong>Última actualización:</strong> 2 de junio de 2026</p>

          <h2>1. Información que recopilamos</h2>
          <p>BotBuilder LATAM recopila información que los clientes proporcionan voluntariamente, incluyendo:</p>
          <ul>
            <li>Datos del negocio (nombre, ciudad, horarios, servicios)</li>
            <li>Números de WhatsApp Business</li>
            <li>Configuración de vendedores IA (tono, personalidad, conocimiento)</li>
            <li>Conversaciones entre clientes y los vendedores IA</li>
            <li>Información de contacto y planes contratados</li>
          </ul>

          <h2>2. Cómo usamos la información</h2>
          <p>Usamos esta información para:</p>
          <ul>
            <li>Proporcionar y mejorar nuestros servicios de vendedores IA</li>
            <li>Procesar mensajes a través de WhatsApp e Instagram</li>
            <li>Analizar calidad y oportunidades detectadas</li>
            <li>Cumplir con obligaciones legales</li>
          </ul>

          <h2>3. Compartir información</h2>
          <p>No compartimos información personal con terceros sin consentimiento, excepto:</p>
          <ul>
            <li><strong>Meta/Facebook:</strong> Para integración de WhatsApp e Instagram, según lo autorizado</li>
            <li><strong>Groq:</strong> Para procesamiento de IA (conversaciones anónimas)</li>
            <li>Cuando lo requiera la ley o autoridad competente</li>
          </ul>

          <h2>4. Seguridad</h2>
          <p>Implementamos medidas de seguridad estándar incluyendo encriptación, autenticación y acceso restringido a datos sensibles.</p>

          <h2>5. Derechos del usuario</h2>
          <p>Los usuarios tienen derecho a:</p>
          <ul>
            <li>Acceder a sus datos</li>
            <li>Solicitar corrección o eliminación</li>
            <li>Exportar sus datos en formato legible</li>
            <li>Revocar autorizaciones de terceros</li>
          </ul>
          <p>Para ejercer estos derechos, contacta a: <strong>soporte@botbuilder.lat</strong></p>

          <h2>6. Retención de datos</h2>
          <p>Los datos se retienen mientras la cuenta esté activa. Al cancelar, los datos se conservan por 30 días y luego se eliminan.</p>

          <h2>7. Cambios a esta política</h2>
          <p>Nos reservamos el derecho de actualizar esta política. Notificaremos cambios significativos por email.</p>

          <h2>8. Contacto</h2>
          <p>Para preguntas sobre esta política de privacidad:</p>
          <p><strong>Email:</strong> soporte@botbuilder.lat<br>
          <strong>Dirección:</strong> Latinoamérica</p>

          <div class="actions"><a class="btn primary" href="/">Volver al inicio</a></div>
        </section>
        """
        render_page(self, "Política de Privacidad", body, None, wide=False, public_nav=True)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/webhook/whatsapp":
            self.webhook_whatsapp_handle()
        elif path == "/register":
            self.register()
        elif path == "/login":
            self.login()
        elif path == "/agents/save":
            user = require_user(self)
            if user:
                self.save_agent(user)
        elif path in ("/api/groq-agent", "/api/agent-chat"):
            self.api_groq_agent()
        elif path == "/api/improve-knowledge":
            user = require_user(self)
            if user:
                self.api_improve_knowledge()
        elif path == "/api/platform-help":
            user = require_user(self)
            if user:
                self.api_platform_help()
        elif path == "/api/leads":
            self.api_lead()
        elif path == "/leads/update":
            user = require_user(self)
            if user:
                self.update_lead(user)
        elif path == "/billing/plan":
            user = require_user(self)
            if user:
                self.update_plan(user)
        else:
            self.send_error(404)

    def page_login(self):
        body = """
        <section class="auth-grid login-grid">
          <article class="hero-panel">
            <p class="eyebrow">Agencia IA comercial para LATAM</p>
            <h1>Vendedores virtuales que atienden, califican y derivan por WhatsApp.</h1>
            <p class="hero-copy">Crea vendedores IA entrenados con la forma real de vender de cada negocio: país, tono, costumbres, objeciones, agenda, cotizaciones y seguimiento.</p>
            <div class="feature-row"><span>Chile, México, Colombia y más</span><span>Respuestas en tiempo real</span><span>Oportunidades listas</span></div>
            <div class="signal-grid">
              <div><strong>01</strong><span>El negocio escribe cómo vende.</span></div>
              <div><strong>02</strong><span>El vendedor aprende límites, tono y cultura.</span></div>
              <div><strong>03</strong><span>La conversación convierte consultas en oportunidades.</span></div>
            </div>
            <div class="mini-chat">
              <div class="mini-top"><span></span> Demo vendedor IA</div>
              <p class="mini bot">Hola, soy Luna. Cuéntame qué necesita tu mascota y te ayudo a agendar.</p>
              <p class="mini user">Quiero saber precio de vacunas y reservar.</p>
              <p class="mini bot">Perfecto. Para orientarte bien, dime edad de tu mascota y comuna. Si quieres avanzar rápido, te derivo al WhatsApp del equipo.</p>
            </div>
          </article>
          <article class="card login-card">
            <h2>Entrar</h2>
            <form method="post" action="/login" class="stack">
              <label>Correo<input name="email" type="email" required placeholder="tucorreo@negocio.com"></label>
              <label>Contraseña<input name="password" type="password" required></label>
              <button class="btn primary">Ingresar</button>
            </form>
            <hr>
            <h2>Crear cuenta</h2>
            <form method="post" action="/register" class="stack">
              <label>Nombre<input name="name" required placeholder="Tu nombre"></label>
              <label>Correo<input name="email" type="email" required></label>
              <label>Contraseña<input name="password" type="password" required minlength="4"></label>
              <button class="btn">Crear cuenta</button>
            </form>
          </article>
        </section>
        """
        render_page(self, "Entrar", body, public_nav=True)

    def register(self):
        form = parse_form(self.read_body())
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (name,email,password_hash,created_at) VALUES (?,?,?,?)",
                    (form["name"].strip(), form["email"].lower().strip(), hash_password(form["password"]), now()),
                )
        except sqlite3.IntegrityError:
            redirect(self, "/login?error=email")
            return
        self.create_session(form["email"].lower().strip())

    def login(self):
        form = parse_form(self.read_body())
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (form["email"].lower().strip(),)).fetchone()
        if not user or not verify_password(form["password"], user["password_hash"]):
            redirect(self, "/login?error=login")
            return
        self.create_session(user["email"])

    def create_session(self, email):
        token = secrets.token_urlsafe(24)
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            conn.execute("INSERT INTO sessions (token,user_id,created_at) VALUES (?,?,?)", (token, user["id"], now()))
        ensure_subscription(user["id"])
        self.send_response(302)
        self.send_header("Location", "/dashboard")
        self.send_header("Set-Cookie", cookie_header("sid", sign(token), 60 * 60 * 24 * 30))
        self.end_headers()

    def logout(self):
        sid = unsign(get_cookie(self.headers.get("Cookie"), "sid"))
        if sid:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token=?", (sid,))
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header("Set-Cookie", cookie_header("sid", "", 0))
        self.end_headers()

    def page_dashboard(self, user):
        sub = ensure_subscription(user["id"])
        with db() as conn:
            agents = conn.execute("SELECT * FROM agents WHERE user_id=? ORDER BY updated_at DESC", (user["id"],)).fetchall()
            leads = conn.execute(
                "SELECT COUNT(*) c FROM leads JOIN agents ON agents.id=leads.agent_id WHERE agents.user_id=?",
                (user["id"],),
            ).fetchone()["c"]
            conversations_total = conn.execute(
                "SELECT COUNT(*) c FROM conversations JOIN agents ON agents.id=conversations.agent_id WHERE agents.user_id=?",
                (user["id"],),
            ).fetchone()["c"]
            won_leads = conn.execute(
                "SELECT COUNT(*) c FROM leads JOIN agents ON agents.id=leads.agent_id WHERE agents.user_id=? AND leads.status='ganado'",
                (user["id"],),
            ).fetchone()["c"]
            hot_leads = conn.execute(
                "SELECT COUNT(*) c FROM leads JOIN agents ON agents.id=leads.agent_id WHERE agents.user_id=? AND leads.status IN ('interesado','cotizacion','agendado')",
                (user["id"],),
            ).fetchone()["c"]
            status_counts = conn.execute(
                "SELECT leads.status, COUNT(*) c FROM leads JOIN agents ON agents.id=leads.agent_id WHERE agents.user_id=? GROUP BY leads.status",
                (user["id"],),
            ).fetchall()
            agent_activity = conn.execute(
                "SELECT agents.business_name, COUNT(conversations.id) c FROM agents LEFT JOIN conversations ON conversations.agent_id=agents.id WHERE agents.user_id=? GROUP BY agents.id ORDER BY c DESC LIMIT 4",
                (user["id"],),
            ).fetchall()
            recent_leads = conn.execute(
                "SELECT leads.*, agents.business_name FROM leads JOIN agents ON agents.id=leads.agent_id WHERE agents.user_id=? ORDER BY leads.created_at DESC LIMIT 5",
                (user["id"],),
            ).fetchall()
            recent_convs = conn.execute(
                "SELECT conversations.*, agents.business_name, COUNT(messages.id) messages FROM conversations JOIN agents ON agents.id=conversations.agent_id LEFT JOIN messages ON messages.conversation_id=conversations.id WHERE agents.user_id=? GROUP BY conversations.id ORDER BY conversations.created_at DESC LIMIT 5",
                (user["id"],),
            ).fetchall()
            faqs_by_agent = {a["id"]: conn.execute("SELECT * FROM faqs WHERE agent_id=?", (a["id"],)).fetchall() for a in agents}

        scored = [(a, *quality_score(a, faqs_by_agent.get(a["id"], [])), agent_status(a, faqs_by_agent.get(a["id"], []))) for a in agents]
        avg_quality = round(sum(item[1] for item in scored) / len(scored)) if scored else 0
        ready = sum(1 for item in scored if item[3][1] == "ready")
        active = sum(1 for item in scored if item[3][1] in ("ready", "active"))
        conversion = round((won_leads / leads) * 100) if leads else 0
        agent_cards = "".join([agent_card(a, score, status) for a, score, _checks, status in scored]) or '<div class="empty">Aún no tienes vendedores IA. Crea el primero y pruébalo en minutos.</div>'
        lead_rows = "".join([f"<li><strong>{esc(l['business_name'])}</strong><span>{esc((l['intent'] or 'Nueva oportunidad')[:90])}</span></li>" for l in recent_leads]) or "<li><span>Aún no hay oportunidades recientes.</span></li>"
        conv_rows = "".join([f"<li><strong>{esc(c['business_name'])}</strong><span>{c['messages']} mensajes · {time.strftime('%d/%m %H:%M', time.localtime(c['created_at']))}</span></li>" for c in recent_convs]) or "<li><span>Aún no hay conversaciones recientes.</span></li>"
        status_labels = {"nuevo":"Nuevo","interesado":"Interesado","cotizacion":"Cotización","agendado":"Agendado","contactado":"Contactado","ganado":"Ganado","perdido":"Perdido"}
        status_total = sum(row["c"] for row in status_counts) or 1
        funnel_rows = "".join([f"<div><span>{esc(status_labels.get(row['status'], row['status'] or 'Sin estado'))}</span><strong>{row['c']}</strong><i style='width:{max(6, round(row['c'] / status_total * 100))}%'></i></div>" for row in status_counts]) or "<p class='hint-line'>Aún no hay oportunidades para medir.</p>"
        activity_rows = "".join([f"<li><strong>{esc(a['business_name'])}</strong><span>{a['c']} conversaciones</span></li>" for a in agent_activity]) or "<li><span>Crea un vendedor IA para medir actividad.</span></li>"

        body = f"""
        <section class="control-hero">
          <div><p class="eyebrow">Centro de control · Plan {esc(sub['plan']).title()}</p><h1>Hola, {esc(user['name'])}</h1><p>Administra vendedores IA, oportunidades y conversaciones desde un solo lugar.</p></div>
          <div class="actions"><a class="btn" href="/inbox">Abrir bandeja comercial</a><a class="btn primary big-cta" href="/agents/new">Crear vendedor IA</a></div>
        </section>
        <section class="stats">
          <article><strong>{active}</strong><span>Vendedores activos</span></article>
          <article><strong>{ready}</strong><span>Listos para WhatsApp</span></article>
          <article><strong>{avg_quality}%</strong><span>Calidad promedio</span></article>
          <article><strong>{leads}</strong><span>Oportunidades detectadas</span></article>
          <article><strong>{conversations_total}</strong><span>Conversaciones</span></article>
          <article><strong>{hot_leads}</strong><span>Oportunidades calientes</span></article>
          <article><strong>{conversion}%</strong><span>Conversión a ganado</span></article>
          <article><strong>{won_leads}</strong><span>Ventas ganadas</span></article>
        </section>
        <section class="dashboard-grid">
          <div>
            <section class="sales-grid">
              <article class="card funnel-card"><h2>Embudo de ventas</h2>{funnel_rows}</article>
              <article class="card feed-card"><h2>Vendedores con más actividad</h2><ul>{activity_rows}</ul></article>
            </section>
            <div class="section-row"><h2>Mis vendedores activos</h2><a href="/agents/new">Nuevo</a></div>
            <section class="grid agents-grid">{agent_cards}</section>
          </div>
          <aside class="dash-side">
            <article class="card feed-card"><h2>Oportunidades recientes</h2><ul>{lead_rows}</ul><a class="btn" href="/leads">Ver oportunidades</a></article>
            <article class="card feed-card"><h2>Conversaciones recientes</h2><ul>{conv_rows}</ul><a class="btn" href="/conversations">Ver conversaciones</a></article>
          </aside>
        </section>
        """
        render_page(self, "Panel", body, user, wide=True)
    def page_agent_form(self, user, agent_id=None):
        agent = None
        faqs = []
        if agent_id:
            found = agent_for_user(agent_id, user["id"])
            if not found:
                self.send_error(404)
                return
            agent, faqs = found
        data = dict(agent) if agent else {}
        faq_values = [{"q": f["question"], "a": f["answer"]} for f in faqs] or [{"q": "", "a": ""}, {"q": "", "a": ""}]
        score, checks = quality_score(agent, faqs) if agent else (0, [])
        check_html = "".join([f"<li class=\"{'ok' if ok else 'bad'}\">{esc(label)}</li>" for label, ok in checks])
        rec_html = "".join([f"<li>{esc(r)}</li>" for r in quality_recommendations(agent, faqs)])
        body = f"""
        <section class="page-head">
          <div><p class="eyebrow">Configuración del vendedor IA</p><h1>{'Editar vendedor IA' if agent else 'Crear vendedor IA'}</h1><p>Completa el flujo por pasos. La información del negocio manda; lo demás afina cultura, venta y derivación.</p></div>
          {f'<a class="btn" href="/chat/{agent_id}">Probar conversación</a>' if agent else ''}
        </section>
        <form method="post" action="/agents/save" class="builder wizard-form">
          <input type="hidden" name="agent_id" value="{esc(agent_id or '')}">
          <aside class="builder-side">
            <p class="side-label">Plantillas por rubro</p>
            <button type="button" class="btn" onclick="applyTemplate('veterinaria')">Veterinaria</button>
            <button type="button" class="btn" onclick="applyTemplate('restaurante')">Restaurante</button>
            <button type="button" class="btn" onclick="applyTemplate('tienda')">Tienda online</button>
            <button type="button" class="btn" onclick="applyTemplate('barberia')">Barbería/Spa</button>
            <button type="button" class="btn" onclick="applyTemplate('inmobiliaria')">Inmobiliaria</button>
            <button type="button" class="btn" onclick="applyTemplate('clinica')">Clínica estética</button>
            <div class="quality"><strong>{score}%</strong><span>Calidad del vendedor IA</span><ul>{check_html or '<li>Completa el formulario para medirlo.</li>'}</ul><p class="side-label">Siguiente mejora</p><ul>{rec_html}</ul></div>
          </aside>
          <div class="builder-main">
            <div class="wizard-tabs" id="wizardTabs">
              <button type="button" class="active" data-wizard="1">Negocio</button>
              <button type="button" data-wizard="2">Conocimiento</button>
              <button type="button" data-wizard="3">Cultura y trato</button>
              <button type="button" data-wizard="4">Venta</button>
              <button type="button" data-wizard="5">WhatsApp</button>
              <button type="button" data-wizard="6">Prueba final</button>
            </div>

            <section class="wizard-step active" data-step="1">
              <div class="section-title">Negocio</div>
              <div class="form-grid">
                {input_field('business_name','Nombre del negocio *',data.get('business_name',''), required=True)}
                {select_field('business_type','Rubro',data.get('business_type',''), ['Veterinaria','Restaurante / Cafetería','Tienda online','Barbería / Spa','Inmobiliaria','Clínica estética','Servicios profesionales','Tecnología','Otro'])}
                {select_field('country_market','País o mercado',data.get('country_market','Latinoamérica general'), ['Latinoamérica general','Chile','México','Colombia','Perú','Argentina','Ecuador','Uruguay','Paraguay','Bolivia','Venezuela','Centroamérica','Caribe hispano','Brasil','Estados Unidos hispano'])}
                {input_field('currency','Moneda',data.get('currency',''), placeholder='CLP, MXN, COP, PEN, USD')}
                {input_field('city','Ciudad / país',data.get('city',''))}
                {input_field('hours','Horario',data.get('hours',''))}
              </div>
            </section>

            <section class="wizard-step" data-step="2">
              <div class="section-title">Información del negocio</div>
              {textarea_field('knowledge','Información principal del negocio *',data.get('knowledge',''), 'Cómo funciona el negocio, cómo vende, precios, reglas, garantías, objeciones, límites, cuándo derivar...', True, 'full knowledge')}
              <div class="ai-review"><button type="button" class="btn primary" onclick="improveKnowledge()">Mejorar con IA</button><span>Detecta qué falta y propone una versión más útil para vender.</span></div>
              <div id="improveResult" class="improve-result"></div>
              {textarea_field('services','Productos o servicios',data.get('services',''), 'Lista servicios, condiciones, paquetes, precios o rangos.', False, 'full')}
            </section>

            <section class="wizard-step" data-step="3">
              <div class="section-title">Cultura y trato</div>
              <div class="form-grid">
                {input_field('bot_name','Nombre del vendedor IA',data.get('bot_name','Asistente'))}
                {select_field('language','Idioma',data.get('language','Español'), ['Español','Portugués','Inglés'])}
                {select_field('tone','Tono',data.get('tone','amigable y cercano'), ['amigable y cercano','profesional y confiable','formal y respetuoso','juvenil y dinámico','técnico y preciso','empático y paciente'])}
                {select_field('formality','Formalidad',data.get('formality','cercano y respetuoso'), ['cercano y respetuoso','profesional y directo','muy formal','relajado, sin perder respeto'])}
                {textarea_field('local_vocabulary','Palabras/costumbres locales permitidas',data.get('local_vocabulary',''), 'Modismos suaves, forma de saludar, palabras de venta locales.', False, 'full')}
                {textarea_field('forbidden_vocabulary','Estilos que debe evitar',data.get('forbidden_vocabulary',''), 'No sonar robótico, no garabatos, no demasiados emojis, no inventar precios.', False, 'full')}
              </div>
            </section>

            <section class="wizard-step" data-step="4">
              <div class="section-title">Venta y derivación</div>
              {textarea_field('sales_mission','Trabajo comercial del vendedor IA *',data.get('sales_mission',''), 'Entender necesidad, responder, manejar objeciones, pedir datos y llevar a compra/reserva/cotización/WhatsApp.', True, 'full knowledge')}
              {textarea_field('special_instructions','Instrucciones especiales',data.get('special_instructions',''), 'Reglas internas del negocio.', False, 'full')}
              <div class="section-title">Preguntas frecuentes</div>
              <div id="faqs">{faq_inputs(faq_values)}</div>
              <button type="button" class="btn" onclick="addFaq()">Agregar pregunta frecuente</button>
            </section>

            <section class="wizard-step" data-step="5">
              <div class="section-title">WhatsApp y contacto</div>
              <p class="section-help">Por ahora WhatsApp es el canal principal. Agrega el número donde el negocio quiere recibir clientes; el botón web queda como opción secundaria si el negocio ya tiene página.</p>
              <div class="subsection-title">Canal principal</div>
              <div class="form-grid">
                {input_field('whatsapp','WhatsApp del negocio *',data.get('whatsapp',''), placeholder='+56 9 1234 5678')}
                {input_field('email','Correo de contacto (opcional)',data.get('email',''))}
                {input_field('website','Página web del negocio (opcional)',data.get('website',''))}
                {input_field('channels','Canales activos',(data.get('channels','') or 'WhatsApp').replace('Web, WhatsApp','WhatsApp'), placeholder='WhatsApp')}
                {input_field('avoid_topics','Qué temas debe evitar',data.get('avoid_topics',''), placeholder='Descuentos no aprobados, política, competencia')}
              </div>
              <div class="subsection-title">WhatsApp Business API (respuestas automáticas)</div>
              <p class="section-help">Conecta la API de Meta para que el vendedor IA responda mensajes de WhatsApp automáticamente. Obtén estos datos en <strong>developers.facebook.com</strong> → tu app → WhatsApp → Configuración de API.</p>
              <div class="form-grid">
                {input_field('meta_phone_id','Phone Number ID',data.get('meta_phone_id',''), placeholder='123456789012345')}
                {input_field('meta_access_token','Access Token (permanente)',data.get('meta_access_token',''), placeholder='EAAxxxxx...')}
              </div>
              <div class="subsection-title">Opcional: botón para página web</div>
              <div class="form-grid">
                {input_field('widget_color','Color principal del botón',data.get('widget_color','#1d9e75'), placeholder='#1d9e75')}
                {input_field('widget_title','Nombre visible del vendedor',data.get('widget_title',''), placeholder='Asistente de ventas')}
                {input_field('widget_label','Texto corto del botón',data.get('widget_label',''), placeholder='IA')}
                {input_field('public_slug','Link público del vendedor',data.get('public_slug',''), placeholder='studio-corte')}
                {textarea_field('widget_welcome','Primer mensaje al visitante',data.get('widget_welcome',''), 'Hola, cuéntame qué necesitas y te ayudo a avanzar.', False, 'full')}
                <input type="hidden" name="groq_model" id="groq_model" value="{esc(data.get('groq_model',GROQ_MODEL))}">
              </div>
              <div class="section-title">Vista previa opcional</div>
              <section class="widget-editor">
                <div class="widget-preview">
                  <button type="button" id="previewFab">IA</button>
                  <div class="preview-panel">
                    <header><strong id="previewTitle">Asistente de ventas</strong><span>×</span></header>
                    <div class="preview-messages"><p id="previewWelcome">Hola, cuéntame qué necesitas y te ayudo a avanzar.</p><p class="preview-user">Quiero consultar precios</p></div>
                    <form><input disabled placeholder="Escribe tu consulta..."><button type="button">Enviar</button></form>
                  </div>
                </div>
                <aside>
                  <strong>Primero WhatsApp</strong>
                  <p class="hint-line">Con el WhatsApp cargado ya puedes probar si el vendedor deriva bien. El botón web se usa después, solo si el negocio quiere atender desde su página.</p>
                </aside>
              </section>
            </section>

            <section class="wizard-step" data-step="6">
              <div class="section-title">Prueba final</div>
              <div class="final-grid">
                <article><strong>{score}%</strong><span>Calidad actual</span></article>
                <article><strong>{'Listo' if score >= 80 else 'Pendiente'}</strong><span>Estado para WhatsApp</span></article>
                <article><strong>{'Disponible' if agent else 'Después de guardar'}</strong><span>Conversación de prueba</span></article>
              </div>
              <p class="hint-line">Guarda el vendedor IA y prueba escenarios reales: precio, cliente indeciso, cliente molesto, WhatsApp, agenda o preguntas sin respuesta.</p>
              <div class="actions"><button class="btn primary">Guardar vendedor IA</button>{f'<a class="btn" href="/chat/{agent_id}">Ir a prueba final</a>' if agent else ''}</div>
            </section>

            <div class="wizard-actions"><button type="button" class="btn" onclick="wizardPrev()">Anterior</button><span id="wizardStatus">Paso 1 de 6</span><button type="button" class="btn primary" onclick="wizardNext()">Siguiente</button></div>
          </div>
        </form>
        """
        render_page(self, "Vendedor IA", body, user, wide=True)
    def save_agent(self, user):
        form = parse_form(self.read_body())
        agent_id = form.get("agent_id")
        fields = [
            "business_name","business_type","country_market","currency","city","hours","whatsapp","email","website",
            "bot_name","language","tone","formality","knowledge","services","local_vocabulary","forbidden_vocabulary",
            "sales_mission","special_instructions","channels","avoid_topics","groq_model","widget_color",
            "widget_title","widget_welcome","widget_label","public_slug","meta_phone_id","meta_access_token"
        ]
        values = [form.get(f, "").strip() for f in fields]
        with db() as conn:
            if not values[-1]:
                values[-1] = unique_slug(conn, form.get("business_name", "agente"), agent_id)
            else:
                values[-1] = unique_slug(conn, values[-1], agent_id)
            if agent_id:
                found = conn.execute("SELECT id FROM agents WHERE id=? AND user_id=?", (agent_id, user["id"])).fetchone()
                if not found:
                    self.send_error(403)
                    return
                set_sql = ",".join([f"{f}=?" for f in fields])
                conn.execute(f"UPDATE agents SET {set_sql}, updated_at=? WHERE id=? AND user_id=?", values + [now(), agent_id, user["id"]])
                aid = int(agent_id)
                conn.execute("DELETE FROM faqs WHERE agent_id=?", (aid,))
            else:
                sub = conn.execute("SELECT * FROM subscriptions WHERE user_id=?", (user["id"],)).fetchone()
                if not sub:
                    conn.execute(
                        "INSERT INTO subscriptions (user_id,plan,agent_limit,message_limit,status,created_at) VALUES (?,?,?,?,?,?)",
                        (user["id"], "starter", 2, 300, "demo", now()),
                    )
                    sub = conn.execute("SELECT * FROM subscriptions WHERE user_id=?", (user["id"],)).fetchone()
                current_agents = conn.execute("SELECT COUNT(*) c FROM agents WHERE user_id=?", (user["id"],)).fetchone()["c"]
                if current_agents >= sub["agent_limit"]:
                    redirect(self, "/billing")
                    return
                placeholders = ",".join(["?"] * len(fields))
                cur = conn.execute(
                    f"INSERT INTO agents (user_id,{','.join(fields)},created_at,updated_at) VALUES (?,{placeholders},?,?)",
                    [user["id"]] + values + [now(), now()],
                )
                aid = cur.lastrowid
            for i in range(1, 7):
                q = form.get(f"faq_q_{i}", "").strip()
                a = form.get(f"faq_a_{i}", "").strip()
                if q and a:
                    conn.execute("INSERT INTO faqs (agent_id,question,answer) VALUES (?,?,?)", (aid, q, a))
        redirect(self, f"/agents/{aid}/edit")

    def page_chat(self, agent_id):
        found = public_agent(agent_id)
        if not found:
            self.send_error(404)
            return
        agent, faqs = found
        widget_color = agent["widget_color"] or "#1d9e75"
        widget_title = agent["widget_title"] or agent["bot_name"] or "Asistente comercial"
        widget_welcome = agent["widget_welcome"] or "Hola, cuéntame qué necesitas y te ayudo a avanzar."
        widget_label = agent["widget_label"] or "IA"
        slug = agent["public_slug"] or str(agent_id)
        base = get_base_url(self)
        install = f'<script src="{base}/widget/{esc(slug)}.js"></script>'
        link_url = f"{base}/l/{esc(slug)}"
        wa = whatsapp_link(agent)
        body = f"""
        <section class="page-head">
          <div><p class="eyebrow">Prueba real del vendedor</p><h1>{esc(agent['bot_name'] or 'Vendedor IA')} de {esc(agent['business_name'])}</h1><p>Prueba cómo atiende, entiende al cliente y lo deriva a WhatsApp. El botón web queda como opción adicional.</p></div>
          <a class="btn" href="{wa}" target="_blank">Conectar WhatsApp</a>
        </section>
        <section class="chat-layout">
          <article class="chat-card">
            <div id="chat" class="chat-box">
              <div class="msg bot">Hola, soy {esc(agent['bot_name'] or 'tu asistente comercial')}. Cuéntame qué necesitas y te ayudo a avanzar.</div>
            </div>
            <form id="chatForm" class="chat-form" onsubmit="sendMessage(event,{agent_id})">
              <input id="chatInput" placeholder="Escribe como cliente: quiero precio, reservar, consultar horario...">
              <button class="btn primary">Enviar</button>
            </form>
          </article>
          <aside class="card">
            <h2>WhatsApp del negocio</h2>
            <p class="hint-line">Este es el canal principal. Úsalo para confirmar reservas, enviar cotizaciones o cerrar ventas.</p>
            <a class="btn primary" href="{wa}" target="_blank">Abrir WhatsApp</a>
            <h2>Link de bio</h2>
            <p class="hint-line">Página tipo Linktree para Instagram, anuncios, tarjetas o QR. Es la opción más fácil para vender sin tener página web.</p>
            <pre>{link_url}</pre>
            <a class="btn primary" href="/l/{esc(slug)}" target="_blank">Ver link comercial</a>
            <button class="btn" onclick="copyText(`{link_url}`)">Copiar link comercial</button>
            <h2>Escenarios de prueba</h2>
            <button class="btn" onclick="quickAsk('Hola, quiero saber precios y disponibilidad')">Cliente pregunta precio</button>
            <button class="btn" onclick="quickAsk('Estoy interesado, pero no sé si esto es para mí')">Cliente indeciso</button>
            <button class="btn" onclick="quickAsk('Estoy molesto porque nadie me respondió ayer')">Cliente molesto</button>
            <button class="btn" onclick="quickAsk('¿Me pueden hablar por WhatsApp?')">Cliente quiere WhatsApp</button>
            <button class="btn" onclick="quickAsk('Quiero agendar para esta semana')">Cliente quiere agendar</button>
            <button class="btn" onclick="quickAsk('¿Tienen una promoción que no aparece en la web?')">Pregunta sin respuesta</button>
            <h2>Opcional: botón web</h2>
            <p class="hint-line">Si el negocio tiene página web, este código muestra un botón de atención. No es obligatorio para vender por WhatsApp.</p>
            <pre>{esc(install)}</pre>
            <button class="btn" onclick="copyText(`{esc(install)}`)">Copiar botón web</button>
          </aside>
        </section>
        """
        render_page(self, "Prueba del vendedor", body, current_user(self), wide=True)

    def api_groq_agent(self):
        body = self.read_body()
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            json_response(self, {"error": "JSON inválido"}, 400)
            return
        try:
            agent_id = int(data.get("agent_id") or 0)
        except (TypeError, ValueError):
            json_response(self, {"error": "agent_id inválido"}, 400)
            return
        found = public_agent(agent_id)
        if not found:
            json_response(self, {"error": "Vendedor IA no encontrado"}, 404)
            return
        agent, faqs = found
        with db() as conn:
            owner_id = agent["user_id"]
            sub = conn.execute("SELECT * FROM subscriptions WHERE user_id=?", (owner_id,)).fetchone()
            if sub:
                used = conn.execute(
                    "SELECT COUNT(*) c FROM messages JOIN conversations ON conversations.id=messages.conversation_id JOIN agents ON agents.id=conversations.agent_id WHERE agents.user_id=? AND messages.role='user'",
                    (owner_id,),
                ).fetchone()["c"]
                if used >= sub["message_limit"]:
                    json_response(self, {"reply": "Este vendedor IA alcanzó el límite de mensajes del plan actual. El negocio puede actualizar su plan para continuar.", "conversation_id": None, "intent": "", "lead_created": False})
                    return
        messages = normalize_messages(data.get("messages") or [])
        visitor = data.get("visitor") or {}
        with db() as conn:
            conv_id = data.get("conversation_id")
            if not conv_id:
                cur = conn.execute(
                    "INSERT INTO conversations (agent_id,visitor_name,visitor_contact,intent,created_at) VALUES (?,?,?,?,?)",
                    (agent_id, visitor.get("name", ""), visitor.get("contact", ""), data.get("intent", ""), now()),
                )
                conv_id = cur.lastrowid
            last_user = messages[-1]["content"] if messages else ""
            if last_user:
                conn.execute("INSERT INTO messages (conversation_id,role,content,created_at) VALUES (?,?,?,?)", (conv_id, "user", last_user, now()))
                conn.execute(
                    "UPDATE conversations SET visitor_contact=COALESCE(NULLIF(visitor_contact,''), ?), intent=COALESCE(NULLIF(intent,''), ?) WHERE id=?",
                    (visitor.get("contact", "") or extract_contact(last_user), infer_intent(last_user), conv_id),
                )
        reply = call_groq(agent, faqs, messages)
        lead_created = False
        with db() as conn:
            conn.execute("INSERT INTO messages (conversation_id,role,content,created_at) VALUES (?,?,?,?)", (conv_id, "assistant", reply, now()))
            if detect_lead(messages[-1]["content"] if messages else ""):
                last_text = messages[-1]["content"] if messages else ""
                contact = visitor.get("contact", "") or extract_contact(last_text)
                intent = infer_intent(last_text)
                lead_created = upsert_lead(conn, agent_id, conv_id, visitor.get("name", ""), contact, intent, last_text)
        json_response(self, {"reply": reply, "conversation_id": conv_id, "intent": infer_intent(messages[-1]["content"] if messages else ""), "lead_created": lead_created})

    def webhook_whatsapp_verify(self):
        """Verifica el webhook con Meta (GET request)."""
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        mode = qs.get("hub.mode", [""])[0]
        token = qs.get("hub.verify_token", [""])[0]
        challenge = qs.get("hub.challenge", [""])[0]

        if mode == "subscribe" and token == META_WEBHOOK_TOKEN:
            payload = challenge.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_error(403, "Webhook verification failed")

    def webhook_whatsapp_handle(self):
        """Recibe y procesa mensajes de WhatsApp desde Meta."""
        body = self.read_body()
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            json_response(self, {"error": "JSON inválido"}, 400)
            return

        json_response(self, {"status": "received"})

        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for message in value.get("messages", []):
                    self._process_whatsapp_message(value, message)

    def _process_whatsapp_message(self, value, message):
        """Procesa un mensaje de WhatsApp y responde usando el agente configurado."""
        phone_number_id = value.get("metadata", {}).get("phone_number_id", "")
        sender = message.get("from", "")
        msg_text = clean_message_text(message.get("text", {}).get("body", ""), 2500)

        if not msg_text or not sender or not phone_number_id:
            return

        with db() as conn:
            agent_row = conn.execute(
                "SELECT * FROM agents WHERE meta_phone_id=? LIMIT 1",
                (phone_number_id,),
            ).fetchone()
            if not agent_row:
                return

            agent_id = agent_row["id"]
            user_id = agent_row["user_id"]

            sub = conn.execute("SELECT * FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
            if sub:
                month_start = int(time.time()) - 30 * 86400
                used = conn.execute(
                    "SELECT COUNT(*) c FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE agent_id=?) AND created_at > ? AND role='assistant'",
                    (agent_id, month_start),
                ).fetchone()["c"]
                if used >= sub["message_limit"]:
                    return

            faqs = conn.execute("SELECT * FROM faqs WHERE agent_id=? ORDER BY id", (agent_id,)).fetchall()
            conv_id, history = get_or_create_whatsapp_conversation(conn, agent_id, sender)

            history.append({"role": "user", "content": msg_text})
            conn.execute(
                "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?,?,?,?)",
                (conv_id, "user", msg_text, now()),
            )

            reply = call_groq(agent_row, faqs, history)

            conn.execute(
                "INSERT INTO messages (conversation_id, role, content, created_at) VALUES (?,?,?,?)",
                (conv_id, "assistant", reply, now()),
            )

            if detect_lead(msg_text):
                intent = infer_intent(msg_text)
                contact = extract_contact(msg_text) or sender
                upsert_lead(conn, agent_id, conv_id, "", contact, intent, msg_text[:300])

        access_token = agent_row["meta_access_token"] or META_ACCESS_TOKEN
        send_whatsapp_message(phone_number_id, access_token, sender, reply)

    def api_lead(self):
        data = json.loads(self.read_body().decode("utf-8"))
        agent_id = int(data.get("agent_id") or 0)
        with db() as conn:
            upsert_lead(conn, agent_id, data.get("conversation_id"), data.get("name", ""), data.get("contact", ""), data.get("intent", ""), data.get("notes", ""))
        json_response(self, {"ok": True})

    def update_lead(self, user):
        form = parse_form(self.read_body())
        lead_id = int(form.get("lead_id") or 0)
        status = form.get("status", "nuevo")
        notes = form.get("notes", "")
        with db() as conn:
            lead = conn.execute(
                "SELECT leads.id FROM leads JOIN agents ON agents.id=leads.agent_id WHERE leads.id=? AND agents.user_id=?",
                (lead_id, user["id"]),
            ).fetchone()
            if not lead:
                self.send_error(404)
                return
            conn.execute("UPDATE leads SET status=?, notes=? WHERE id=?", (status, notes, lead_id))
        redirect(self, "/leads")

    def update_plan(self, user):
        form = parse_form(self.read_body())
        plans = {
            "starter": (2, 300),
            "pro": (10, 3000),
            "agency": (50, 20000),
        }
        plan = form.get("plan", "starter")
        if plan not in plans:
            plan = "starter"
        agent_limit, message_limit = plans[plan]
        with db() as conn:
            conn.execute(
                "INSERT INTO subscriptions (user_id,plan,agent_limit,message_limit,status,created_at) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan=excluded.plan, agent_limit=excluded.agent_limit, message_limit=excluded.message_limit, status=excluded.status",
                (user["id"], plan, agent_limit, message_limit, "demo", now()),
            )
        redirect(self, "/billing")

    def api_improve_knowledge(self):
        try:
            data = json.loads(self.read_body().decode("utf-8"))
        except json.JSONDecodeError:
            json_response(self, {"error": "JSON inválido"}, 400)
            return
        json_response(self, improve_knowledge_text(data))

    def api_platform_help(self):
        try:
            data = json.loads(self.read_body().decode("utf-8"))
        except json.JSONDecodeError:
            json_response(self, {"error": "JSON inválido"}, 400)
            return
        message = clean_message_text(data.get("message", ""), 1200)
        path = clean_message_text(data.get("path", "/"), 300)
        if not message:
            json_response(self, {"reply": route_help(path)})
            return
        destination = platform_destination(message, path)
        reply = platform_help_reply(message, path)
        if destination and destination["url"] != path:
            reply = f"{reply}\n\nPuedo llevarte al apartado correcto para hacerlo."
        json_response(self, {"reply": reply, "action": destination})

    def serve_widget_js(self):
        script = r"""
(function(){
  const current = document.currentScript;
  const agentId = current && current.dataset.agentId;
  const endpoint = (current && current.dataset.endpoint) || "/api/agent-chat";
  const color = (current && current.dataset.color) || "#1d9e75";
  const title = (current && current.dataset.title) || "Asistente comercial";
  const welcome = (current && current.dataset.welcome) || "Hola, cuéntame qué necesitas y te ayudo a avanzar.";
  const label = (current && current.dataset.label) || "IA";
  if(!agentId || document.getElementById("bb-widget-root")) return;
  const safe = (text) => String(text || "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
  const root = document.createElement("div");
  root.id = "bb-widget-root";
  root.innerHTML = `
    <button class="bb-fab">${safe(label)}</button>
    <section class="bb-panel" hidden>
      <header><strong>${safe(title)}</strong><button type="button">×</button></header>
      <div class="bb-messages"><p class="bot">${safe(welcome)}</p></div>
      <form><input placeholder="Escribe tu consulta..."><button>Enviar</button></form>
    </section>`;
  const style = document.createElement("style");
  style.textContent = `
    #bb-widget-root{position:fixed;right:22px;bottom:22px;z-index:999999;font-family:Inter,system-ui,sans-serif}
    #bb-widget-root .bb-fab{min-width:58px;height:58px;border-radius:999px;border:0;background:${color};color:white;font-weight:900;box-shadow:0 0 0 4px color-mix(in srgb, ${color} 20%, transparent),0 12px 34px rgba(0,0,0,.24);cursor:pointer;padding:0 16px;transition:.18s ease}
    #bb-widget-root .bb-fab:hover{box-shadow:0 0 0 6px color-mix(in srgb, ${color} 28%, transparent),0 0 34px color-mix(in srgb, ${color} 42%, transparent),0 16px 42px rgba(0,0,0,.28);transform:translateY(-1px)}
    #bb-widget-root .bb-panel{width:min(360px,calc(100vw - 32px));height:520px;background:#f2fbf8;border:1px solid #aecac1;border-radius:14px;box-shadow:0 22px 70px rgba(0,0,0,.24);overflow:hidden}
    #bb-widget-root header{background:#10231f;color:white;padding:13px 14px;display:flex;justify-content:space-between;align-items:center}
    #bb-widget-root header button{background:transparent;color:white;border:0;font-size:22px;cursor:pointer}
    #bb-widget-root .bb-messages{height:405px;overflow:auto;padding:14px;background:#edf8f4;display:flex;flex-direction:column;gap:9px}
    #bb-widget-root p{margin:0;max-width:86%;padding:10px 12px;border-radius:14px;line-height:1.4;font-size:14px}
    #bb-widget-root .bot{align-self:flex-start;background:white;color:#10201d;border-bottom-left-radius:4px}
    #bb-widget-root .user{align-self:flex-end;background:${color};color:white;border-bottom-right-radius:4px}
    #bb-widget-root form{display:flex;gap:8px;padding:10px;background:white;border-top:1px solid #cfe3dd}
    #bb-widget-root input{flex:1;border:1px solid #aecac1;border-radius:8px;padding:10px}
    #bb-widget-root form button{border:0;border-radius:8px;background:${color};color:white;font-weight:800;padding:0 12px}`;
  document.head.appendChild(style);
  document.body.appendChild(root);
  const fab = root.querySelector(".bb-fab");
  const panel = root.querySelector(".bb-panel");
  const close = root.querySelector("header button");
  const messages = root.querySelector(".bb-messages");
  const form = root.querySelector("form");
  const input = root.querySelector("input");
  let conversationId = null;
  let history = [];
  function add(role,text){ const p=document.createElement("p"); p.className=role; p.textContent=text; messages.appendChild(p); messages.scrollTop=messages.scrollHeight; return p; }
  fab.onclick = () => { panel.hidden = false; fab.hidden = true; };
  close.onclick = () => { panel.hidden = true; fab.hidden = false; };
  form.onsubmit = async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if(!text) return;
    input.value = "";
    add("user", text);
    history.push({role:"user", content:text});
    const pending = add("bot", "Escribiendo...");
    const res = await fetch(endpoint, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({agent_id:Number(agentId), conversation_id:conversationId, messages:history})});
    const data = await res.json();
    conversationId = data.conversation_id;
    pending.textContent = data.reply || "No pude responder.";
    history.push({role:"assistant", content:pending.textContent});
  };
})();"""
        payload = script.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def serve_public_widget_js(self, slug):
        found = public_agent_by_slug(slug)
        if not found:
            self.send_error(404)
            return
        agent, _faqs = found
        color = agent["widget_color"] or "#1d9e75"
        title = agent["widget_title"] or agent["bot_name"] or "Asistente comercial"
        welcome = agent["widget_welcome"] or "Hola, cuéntame qué necesitas y te ayudo a avanzar."
        label = agent["widget_label"] or "IA"
        base = get_base_url(self)
        script = f"""(function(){{
  var s=document.createElement('script');
  s.src={json.dumps(base + '/widget.js')};
  s.dataset.agentId={json.dumps(str(agent["id"]))};
  s.dataset.endpoint={json.dumps(base + '/api/agent-chat')};
  s.dataset.color={json.dumps(color)};
  s.dataset.title={json.dumps(title)};
  s.dataset.welcome={json.dumps(welcome)};
  s.dataset.label={json.dumps(label)};
  document.currentScript.after(s);
}})();"""
        payload = script.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def page_public_agent(self, slug):
        found = public_agent_by_slug(slug)
        if not found:
            self.send_error(404)
            return
        agent, _faqs = found
        base = get_base_url(self)
        widget_url = f"{base}/widget/{esc(agent['public_slug'])}.js"
        body = f"""
        <section class="public-agent">
          <div>
            <p class="eyebrow">Vendedor IA activo</p>
            <h1>{esc(agent['business_name'])}</h1>
            <p>{esc(public_summary(agent))}</p>
            <div class="actions"><a class="btn primary" href="/chat/{agent['id']}">Probar vendedor</a><a class="btn" target="_blank" href="{whatsapp_link(agent)}">WhatsApp</a></div>
          </div>
          <aside class="card">
            <h2>Botón web opcional</h2>
            <p class="hint-line">Para vender ahora, usa WhatsApp. Este código sirve solo si también quieres mostrar el vendedor en una página web.</p>
            <pre>&lt;script src="{widget_url}"&gt;&lt;/script&gt;</pre>
            <button class="btn" onclick="copyText(`&lt;script src='{widget_url}'&gt;&lt;/script&gt;`)">Copiar botón web</button>
          </aside>
        </section>
        <script src="{widget_url}"></script>
        """
        render_page(self, agent["business_name"], body, None, wide=True)

    def page_link_bio(self, slug):
        found = public_agent_by_slug(slug)
        if not found:
            self.send_error(404)
            return
        agent, _faqs = found
        base = get_base_url(self)
        link_url = f"{base}/l/{esc(agent['public_slug'] or slug)}"
        wa_url = whatsapp_link(agent)
        website = (agent["website"] or "").strip()
        email = (agent["email"] or "").strip()
        services = [s.strip() for s in (agent["services"] or "").replace("\n", ",").split(",") if s.strip()]
        service_tags = "".join(f"<span>{esc(item)}</span>" for item in services[:6])
        optional_links = ""
        if website:
            href = website if website.startswith(("http://", "https://")) else f"https://{website}"
            optional_links += f'<a class="bio-link" target="_blank" href="{esc(href)}"><strong>Visitar sitio web</strong><span>Ver catálogo, servicios o información oficial</span></a>'
        if email:
            optional_links += f'<a class="bio-link" href="mailto:{esc(email)}"><strong>Enviar correo</strong><span>Contacto formal para empresas o consultas detalladas</span></a>'
        body = f"""
        <section class="link-bio">
          <div class="bio-shell">
            <div class="bio-avatar">{esc((agent['business_name'] or 'IA')[:2].upper())}</div>
            <p class="eyebrow">Link comercial</p>
            <h1>{esc(agent['business_name'])}</h1>
            <p>{esc(public_summary(agent))}</p>
            <div class="bio-tags">{service_tags or '<span>Atención por WhatsApp</span><span>Consultas y reservas</span><span>Cotizaciones</span>'}</div>
            <div class="bio-actions">
              <a class="bio-link primary" target="_blank" href="{wa_url}"><strong>Hablar por WhatsApp</strong><span>Respuesta directa del negocio</span></a>
              <a class="bio-link" href="/chat/{agent['id']}"><strong>Probar vendedor IA</strong><span>Simular una consulta antes de escribir</span></a>
              {optional_links}
            </div>
            <button class="btn" onclick="copyText(`{link_url}`)">Copiar link para compartir</button>
          </div>
        </section>
        """
        render_page(self, f"Link comercial de {agent['business_name']}", body, None, wide=True)

    def page_inbox(self, user):
        with db() as conn:
            convs = conn.execute(
                "SELECT conversations.*, agents.business_name, agents.whatsapp, GROUP_CONCAT(CASE WHEN messages.role='user' THEN messages.content ELSE NULL END, ' ') user_text, MAX(messages.created_at) last_message_at FROM conversations JOIN agents ON agents.id=conversations.agent_id LEFT JOIN messages ON messages.conversation_id=conversations.id WHERE agents.user_id=? GROUP BY conversations.id ORDER BY conversations.created_at DESC LIMIT 30",
                (user["id"],),
            ).fetchall()
            first_id = convs[0]["id"] if convs else 0
            messages = conn.execute("SELECT * FROM messages WHERE conversation_id=? ORDER BY created_at", (first_id,)).fetchall() if first_id else []
            leads = conn.execute("SELECT * FROM leads WHERE conversation_id=? ORDER BY id DESC LIMIT 1", (first_id,)).fetchone() if first_id else None
        selected = convs[0] if convs else None
        items = []
        for c in convs:
            contact = c["visitor_contact"] or extract_contact(c["user_text"] or "")
            intent = c["intent"] or infer_intent(c["user_text"] or "")
            priority_label, priority_key = conversation_priority(c["user_text"] or "", contact)
            items.append(f"<a class='inbox-item {'active' if selected and c['id']==selected['id'] else ''}' href='/conversations/{c['id']}'><strong>{esc(c['business_name'])}</strong><span>{esc(intent)} · {priority_label}</span><small>{esc(contact or 'contacto pendiente')}</small></a>")
        bubbles = "".join([f"<div class='msg {('bot' if m['role'] == 'assistant' else 'user')}'>{esc(m['content'])}</div>" for m in messages]) or "<div class='msg bot'>Aún no hay mensajes seleccionados.</div>"
        if selected:
            full_text = selected["user_text"] or ""
            contact = selected["visitor_contact"] or extract_contact(full_text)
            intent = selected["intent"] or infer_intent(full_text)
            priority_label, priority_key = conversation_priority(full_text, contact)
            next_action = next_action_for_intent(intent, contact)
            wa_digits = "".join(ch for ch in (contact or selected["whatsapp"] or "") if ch.isdigit())
            wa_url = f"https://wa.me/{wa_digits}?text={urllib.parse.quote('Hola, te escribo por tu consulta a ' + selected['business_name'])}" if wa_digits else "https://wa.me/"
            side = f"<span class='priority {priority_key}'>{priority_label}</span><h2>{esc(intent)}</h2><p>{esc(next_action)}</p><p><strong>Contacto:</strong> {esc(contact or 'pendiente')}</p><p><strong>Estado:</strong> {esc(leads['status'] if leads else 'sin oportunidad')}</p><a class='btn primary' target='_blank' href='{wa_url}'>Responder WhatsApp</a><a class='btn' href='/conversations/{selected['id']}'>Ver detalle</a>"
        else:
            side = "<p>No hay conversaciones todavía. Prueba un vendedor IA o conecta WhatsApp para empezar a detectar oportunidades.</p>"
        body = f"""
        <section class="page-head"><div><p class="eyebrow">Bandeja comercial</p><h1>Atención y seguimiento</h1><p>Revisa quién escribió, qué necesita y cuál es el siguiente paso recomendado.</p></div><a class="btn primary" href="/agents/new">Crear vendedor IA</a></section>
        <section class="crm-layout">
          <aside class="crm-list">{''.join(items) or '<div class="empty">Sin conversaciones.</div>'}</aside>
          <article class="chat-card"><div class="chat-box">{bubbles}</div></article>
          <aside class="card crm-side">{side}</aside>
        </section>
        """
        render_page(self, "Bandeja comercial", body, user, wide=True)

    def page_billing(self, user):
        sub = ensure_subscription(user["id"])
        plans = [
            ("starter", "Inicial", "$19", "Para probar con un negocio y empezar a captar oportunidades", "2 vendedores IA", "300 mensajes/mes"),
            ("pro", "Crecimiento", "$49", "Para negocios que ya reciben consultas y quieren vender más", "10 vendedores IA", "3.000 mensajes/mes"),
            ("agency", "Agencia", "$149", "Para manejar varios negocios o clientes desde una sola cuenta", "50 vendedores IA", "20.000 mensajes/mes"),
        ]
        cards = []
        for key, name, price, desc, agents, messages in plans:
            active = key == sub["plan"]
            cards.append(f"""
            <article class="pricing-card {'active' if active else ''}">
              <span>{'Plan actual' if active else 'Disponible'}</span>
              <h2>{name}</h2><strong>{price}<small>/mes</small></strong>
              <p>{desc}</p><ul><li>{agents}</li><li>{messages}</li><li>WhatsApp, oportunidades y bandeja comercial incluidos</li></ul>
              <form method="post" action="/billing/plan"><input type="hidden" name="plan" value="{key}"><button class="btn {'primary' if not active else ''}">{'Mantener plan' if active else 'Elegir plan'}</button></form>
            </article>
            """)
        body = f"""
        <section class="page-head"><div><p class="eyebrow">Planes y crecimiento</p><h1>Elige cómo escalar tus vendedores IA</h1><p>Activa más agentes, más conversaciones y más capacidad comercial a medida que crece tu negocio.</p></div></section>
        <section class="pricing-grid">{''.join(cards)}</section>
        <section class="card"><h2>Próximo paso para cobrar</h2><p>Conectar pagos, aplicar límites automáticamente y activar dominios reales para cada cliente.</p></section>
        """
        render_page(self, "Planes", body, user, wide=True)

    def page_leads(self, user):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        status_filter = (qs.get("status", [""])[0] or "").strip()
        agent_filter = int(qs.get("agent", ["0"])[0] or 0)
        where = ["agents.user_id=?"]
        params = [user["id"]]
        if status_filter:
            where.append("leads.status=?")
            params.append(status_filter)
        if agent_filter:
            where.append("leads.agent_id=?")
            params.append(agent_filter)
        with db() as conn:
            agents = conn.execute("SELECT id,business_name FROM agents WHERE user_id=? ORDER BY business_name", (user["id"],)).fetchall()
            leads = conn.execute(
                f"SELECT leads.*, agents.business_name, agents.whatsapp FROM leads JOIN agents ON agents.id=leads.agent_id WHERE {' AND '.join(where)} ORDER BY leads.created_at DESC",
                tuple(params),
            ).fetchall()
        agent_opts = "<option value='0'>Todos los vendedores</option>" + "".join([f"<option value='{a['id']}' {'selected' if agent_filter == a['id'] else ''}>{esc(a['business_name'])}</option>" for a in agents])
        status_opts = "".join([f"<option value='{s}' {'selected' if status_filter == s else ''}>{label}</option>" for s,label in [("","Todos los estados"),("nuevo","Nuevo"),("interesado","Interesado"),("cotizacion","Cotización"),("agendado","Agendado"),("contactado","Contactado"),("ganado","Ganado"),("perdido","Perdido")]])
        rows = "".join([lead_row(l) for l in leads])
        body = f"""
        <section class='page-head'><div><p class='eyebrow'>Seguimiento comercial</p><h1>Oportunidades detectadas</h1><p>Aquí aparecen los clientes que dejaron una señal de interés: precio, reserva, compra o contacto por WhatsApp.</p></div></section>
        <form class='filters' method='get'><select name='agent'>{agent_opts}</select><select name='status'>{status_opts}</select><button class='btn'>Ver resultados</button><a class='btn' href='/leads'>Mostrar todo</a></form>
        <table class='lead-table'><thead><tr><th>Cliente detectado</th><th>Qué quiere el cliente</th><th>Seguimiento comercial</th><th>Qué hacer ahora</th></tr></thead><tbody>{rows or '<tr><td colspan=4>Aún no hay oportunidades con este filtro.</td></tr>'}</tbody></table>
        """
        render_page(self, "Oportunidades", body, user, wide=True)
    def page_conversations(self, user):
        with db() as conn:
            convs = conn.execute(
                "SELECT conversations.*, agents.business_name, COUNT(messages.id) messages, GROUP_CONCAT(CASE WHEN messages.role='user' THEN messages.content ELSE NULL END, ' ') user_text FROM conversations JOIN agents ON agents.id=conversations.agent_id LEFT JOIN messages ON messages.conversation_id=conversations.id WHERE agents.user_id=? GROUP BY conversations.id ORDER BY conversations.created_at DESC",
                (user["id"],),
            ).fetchall()
        rows = []
        for c in convs:
            intent = c["intent"] or infer_intent(c["user_text"] or "")
            contact = c["visitor_contact"] or extract_contact(c["user_text"] or "")
            priority_label, priority_key = conversation_priority(c["user_text"] or "", contact)
            action = next_action_for_intent(intent, contact)
            rows.append(f"<tr><td>{esc(c['business_name'])}<span>{time.strftime('%Y-%m-%d %H:%M', time.localtime(c['created_at']))}</span></td><td>{esc(contact or 'pendiente')}</td><td><span class='intent-pill'>{esc(intent)}</span></td><td><span class='priority {priority_key}'>{priority_label}</span></td><td>{esc(action)}</td><td>{c['messages']}</td><td><a class='btn' href='/conversations/{c['id']}'>Abrir</a></td></tr>")
        body = f"<section class='page-head'><div><p class='eyebrow'>Historial inteligente</p><h1>Conversaciones del negocio</h1><p>Revisa qué pidió cada cliente, qué tan importante es y qué conviene hacer después.</p></div></section><table><thead><tr><th>Negocio</th><th>Contacto detectado</th><th>Qué pidió</th><th>Prioridad</th><th>Siguiente paso sugerido</th><th>Mensajes</th><th></th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=7>Aún no hay conversaciones.</td></tr>'}</tbody></table>"
        render_page(self, "Conversaciones", body, user, wide=True)

    def page_conversation_detail(self, user, conv_id):
        with db() as conn:
            conv = conn.execute(
                "SELECT conversations.*, agents.business_name, agents.id agent_id, agents.whatsapp FROM conversations JOIN agents ON agents.id=conversations.agent_id WHERE conversations.id=? AND agents.user_id=?",
                (conv_id, user["id"]),
            ).fetchone()
            if not conv:
                self.send_error(404)
                return
            messages = conn.execute("SELECT * FROM messages WHERE conversation_id=? ORDER BY created_at", (conv_id,)).fetchall()
        full_text = "\n".join([m["content"] for m in messages if m["role"] == "user"])
        intent = infer_intent(full_text)
        contact = conv["visitor_contact"] or extract_contact(full_text)
        summary = summarize_conversation(messages)
        priority_label, priority_key = conversation_priority(full_text, contact)
        next_action = next_action_for_intent(intent, contact)
        wa_digits = "".join(ch for ch in (contact or conv["whatsapp"] or "") if ch.isdigit())
        wa_url = f"https://wa.me/{wa_digits}?text={urllib.parse.quote('Hola, te escribo por tu consulta a ' + conv['business_name'])}" if wa_digits else "https://wa.me/"
        bubbles = "".join([f"<div class='msg {('bot' if m['role'] == 'assistant' else 'user')}'>{esc(m['content'])}</div>" for m in messages])
        body = f"""
        <section class='page-head'><div><p class='eyebrow'>Detalle inteligente</p><h1>{esc(conv['business_name'])}</h1><p>Intención: <strong>{esc(intent)}</strong> · Prioridad: <strong>{priority_label}</strong> · Contacto: <strong>{esc(contact or 'pendiente')}</strong></p></div><a class='btn primary' target='_blank' href='{wa_url}'>Abrir WhatsApp</a></section>
        <section class='conversation-detail'>
          <article class='chat-card'><div class='chat-box'>{bubbles or '<div class="msg bot">Sin mensajes.</div>'}</div></article>
          <aside class='card smart-summary'><h2>Resumen</h2><span class='priority {priority_key}'>{priority_label}</span><p>{esc(summary)}</p><h2>Próxima acción</h2><p>{esc(next_action)}</p><button class='btn' onclick="copyText(`{esc(summary + ' Próxima acción: ' + next_action)}`)">Copiar resumen</button></aside>
        </section>
        """
        render_page(self, "Conversación", body, user, wide=True)


def input_field(name, label, value="", placeholder="", required=False):
    return f'<label>{esc(label)}<input name="{name}" id="{name}" value="{esc(value)}" placeholder="{esc(placeholder)}" {"required" if required else ""}></label>'


def textarea_field(name, label, value="", placeholder="", required=False, cls=""):
    return f'<label class="{cls}">{esc(label)}<textarea name="{name}" id="{name}" placeholder="{esc(placeholder)}" {"required" if required else ""}>{esc(value)}</textarea></label>'


def select_field(name, label, value, options):
    opts = "".join([f'<option {"selected" if str(o)==str(value) else ""}>{esc(o)}</option>' for o in options])
    return f'<label>{esc(label)}<select name="{name}" id="{name}">{opts}</select></label>'


def faq_inputs(faqs):
    html_parts = []
    for i in range(1, 7):
        item = faqs[i - 1] if i <= len(faqs) else {"q": "", "a": ""}
        html_parts.append(
            f"""
            <div class="faq-row">
              <input name="faq_q_{i}" placeholder="Pregunta frecuente {i}" value="{esc(item.get('q',''))}">
              <textarea name="faq_a_{i}" placeholder="Respuesta">{esc(item.get('a',''))}</textarea>
            </div>
            """
        )
    return "".join(html_parts)


def agent_card(agent, score=None, status=None):
    wa = whatsapp_link(agent)
    link = f"/l/{esc(agent['public_slug'] or str(agent['id']))}"
    if score is None or status is None:
        score, _ = quality_score(agent, [])
        status = ("falta configurar", "draft")
    status_label, status_key = status
    return f"""
    <article class="card agent-card">
      <div class="agent-top"><span>{esc(agent['country_market'] or 'LATAM')}</span><strong>{esc(agent['business_name'])}</strong></div>
      <div class="agent-status {esc(status_key)}">{esc(status_label)} · {score}% calidad</div>
      <p>{esc((agent['knowledge'] or 'Sin base de conocimiento')[:160])}</p>
      <div class="pill-row"><span>{esc(agent['business_type'] or 'Negocio')}</span><span>{esc(agent['tone'] or 'amigable')}</span></div>
      <div class="actions">
        <a class="btn" href="/agents/{agent['id']}/edit">Configurar</a>
        <a class="btn primary" href="/chat/{agent['id']}">Probar</a>
        <a class="btn" href="{wa}" target="_blank">WhatsApp</a>
        <a class="btn" href="{link}" target="_blank">Link comercial</a>
      </div>
    </article>
    """


def lead_row(lead):
    contact = lead["contact"] or ""
    wa_digits = "".join(ch for ch in contact if ch.isdigit()) or "".join(ch for ch in (lead["whatsapp"] or "") if ch.isdigit())
    wa_text = urllib.parse.quote(f"Hola, te escribo por tu consulta sobre {lead['business_name']}.")
    wa_url = f"https://wa.me/{wa_digits}?text={wa_text}" if wa_digits else "https://wa.me/"
    return f"""
    <tr>
      <td><strong>{esc(lead['business_name'])}</strong><span>{esc(lead['name'] or 'Sin nombre')}</span><span>{esc(contact or 'Contacto pendiente')}</span></td>
      <td><span class="intent-pill">{esc(lead['intent'] or 'Consulta general')}</span><p>{esc((lead['notes'] or '')[:160])}</p></td>
      <td>
        <form method="post" action="/leads/update" class="lead-form">
          <input type="hidden" name="lead_id" value="{lead['id']}">
          <select name="status">
            {lead_status_options(lead['status'])}
          </select>
          <textarea name="notes" placeholder="Notas para seguimiento">{esc(lead['notes'] or '')}</textarea>
          <button class="btn">Guardar seguimiento</button>
        </form>
      </td>
      <td><a class="btn primary" target="_blank" href="{wa_url}">Responder por WhatsApp</a>{f'<a class="btn" href="/conversations/{lead["conversation_id"]}">Ver conversación</a>' if lead["conversation_id"] else ''}</td>
    </tr>
    """


def lead_status_options(current):
    labels = [("nuevo", "Nuevo"), ("interesado", "Interesado"), ("cotizacion", "Cotización"), ("agendado", "Agendado"), ("contactado", "Contactado"), ("ganado", "Ganado"), ("perdido", "Perdido")]
    return "".join([f'<option value="{v}" {"selected" if current == v else ""}>{label}</option>' for v, label in labels])


def summarize_conversation(messages):
    user_msgs = [m["content"] for m in messages if m["role"] == "user"]
    if not user_msgs:
        return "No hay mensajes del visitante para resumir."
    text = " ".join(user_msgs)
    intent = infer_intent(text)
    contact = extract_contact(text) or "contacto pendiente"
    return f"Intención principal: {intent}. Contacto detectado: {contact}. Última necesidad expresada: {user_msgs[-1][:180]}"


def whatsapp_link(agent):
    digits = "".join(ch for ch in (agent["whatsapp"] or "") if ch.isdigit())
    text = urllib.parse.quote(f"Hola, quiero consultar sobre {agent['business_name']}.")
    return f"https://wa.me/{digits}?text={text}" if digits else "https://wa.me/"


def public_summary(agent, limit=260):
    text = (agent["knowledge"] or "Atención comercial por WhatsApp para responder dudas, cotizar y coordinar el siguiente paso.").strip()
    text = text.replace("El agente", "El vendedor IA").replace("el agente", "el vendedor IA")
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


CSS = r"""
:root{--bg:#07110f;--panel:#f2fbf8;--soft:#e8f6f1;--text:#10201d;--muted:#63736f;--line:#cfe3dd;--strong:#0f6e56;--green:#1d9e75;--neon:#22f0b7;--blue:#35a7ff;--danger:#a84444;--shadow:0 18px 50px rgba(0,0,0,.16);--r:10px}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,Segoe UI,sans-serif;color:var(--text);background:#081411;min-height:100vh}.bg-grid{position:fixed;inset:0;z-index:-1;background:linear-gradient(180deg,rgba(7,17,15,.1),rgba(245,247,248,.94) 520px),linear-gradient(90deg,rgba(34,240,183,.14) 1px,transparent 1px),linear-gradient(0deg,rgba(53,167,255,.1) 1px,transparent 1px),radial-gradient(ellipse at top,rgba(34,240,183,.36),transparent 48%),#081411;background-size:auto,58px 58px,58px 58px,auto,auto}
a{color:inherit;text-decoration:none}.topbar{width:min(1180px,calc(100% - 32px));margin:14px auto 18px;padding:14px;border:1px solid rgba(148,205,188,.34);border-radius:12px;background:linear-gradient(115deg,rgba(34,240,183,.12),rgba(53,167,255,.08)),rgba(8,20,17,.72);box-shadow:var(--shadow);display:flex;align-items:center;justify-content:space-between;gap:16px;backdrop-filter:blur(16px)}.brand{display:flex;align-items:center;gap:10px;color:#f2fffb}.brand small{display:block;color:rgba(218,245,237,.68);font-size:12px}.mark{width:38px;height:38px;border-radius:9px;background:#10231f;display:grid;place-items:center;font-weight:900}.topbar nav{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.nav-pill{position:relative;display:inline-flex;align-items:center;gap:7px;min-height:34px;padding:8px 11px;border:1px solid rgba(148,205,188,.22);border-radius:999px;background:rgba(234,255,248,.04);color:#d9f4eb;font-size:12px;font-weight:900;line-height:1;transition:.18s ease}.nav-pill:before{content:"";width:6px;height:6px;border-radius:999px;background:rgba(101,255,208,.35);box-shadow:0 0 10px rgba(34,240,183,.18)}.nav-pill:hover,.nav-pill.active{background:rgba(34,240,183,.12);border-color:rgba(34,240,183,.5);color:#f4fffb;box-shadow:0 0 0 1px rgba(34,240,183,.08),0 0 18px rgba(34,240,183,.18);transform:translateY(-1px)}.nav-pill.active:before{background:#65ffd0;box-shadow:0 0 14px rgba(34,240,183,.75)}.nav-pill.logout{background:rgba(255,255,255,.03);color:#bfe5da}.nav-pill.logout:before{background:rgba(255,255,255,.28);box-shadow:none}.shell{width:min(980px,calc(100% - 32px));margin:0 auto 44px}.shell.wide{width:min(1180px,calc(100% - 32px))}
.auth-grid,.chat-layout,.builder{display:grid;grid-template-columns:1.12fr 420px;gap:16px;align-items:start}.hero-panel,.card,.page-head,.builder-main,.builder-side,table{background:linear-gradient(145deg,rgba(236,252,247,.96),rgba(218,242,234,.9));border:1px solid rgba(96,210,177,.55);border-radius:12px;box-shadow:0 0 0 1px rgba(34,240,183,.16),0 0 26px rgba(34,240,183,.12),0 20px 58px rgba(5,18,15,.18);backdrop-filter:blur(14px)}.hero-panel{padding:34px;background:linear-gradient(135deg,rgba(8,22,19,.92),rgba(14,48,41,.84)),linear-gradient(180deg,rgba(242,251,248,.95),rgba(234,247,243,.95));color:#f2fffb;position:relative;overflow:hidden}.hero-panel:before{content:"";position:absolute;inset:0;background:linear-gradient(90deg,rgba(34,240,183,.11) 1px,transparent 1px),linear-gradient(0deg,rgba(53,167,255,.08) 1px,transparent 1px);background-size:36px 36px;mask-image:linear-gradient(180deg,#000,transparent 80%)}.hero-panel>*{position:relative}.hero-panel h1,.page-head h1{font-size:42px;line-height:1.05;margin:8px 0 14px}.hero-panel h1{max-width:720px}.hero-panel p,.page-head p{color:var(--muted);line-height:1.55}.hero-panel .hero-copy{color:#bfe5da;font-size:17px;max-width:620px}.eyebrow{margin:0;color:var(--green);font-size:12px;font-weight:900;text-transform:uppercase;letter-spacing:.08em}.hero-panel .eyebrow{color:#65ffd0}.feature-row,.pill-row{display:flex;gap:8px;flex-wrap:wrap}.feature-row span,.pill-row span{background:rgba(232,246,241,.82);border:1px solid rgba(96,210,177,.35);border-radius:999px;padding:7px 10px;font-size:12px;font-weight:800}.hero-panel .feature-row span{background:rgba(34,240,183,.12);border-color:rgba(34,240,183,.32);color:#ddfff5}.signal-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:22px 0}.signal-grid div{border:1px solid rgba(148,205,188,.28);background:rgba(9,24,21,.72);border-radius:10px;padding:12px}.signal-grid strong{display:block;color:#65ffd0;font-size:13px}.signal-grid span{display:block;color:#c7e9df;font-size:12px;line-height:1.35;margin-top:5px}.mini-chat{border:1px solid rgba(34,240,183,.28);background:rgba(6,16,14,.72);border-radius:14px;padding:14px;margin-top:10px;box-shadow:0 0 35px rgba(34,240,183,.08)}.mini-top{color:#cffbed;font-weight:900;font-size:12px;margin-bottom:10px}.mini-top span{display:inline-block;width:8px;height:8px;background:#22f0b7;border-radius:999px;box-shadow:0 0 12px #22f0b7;margin-right:7px}.mini{max-width:86%;padding:9px 11px;border-radius:14px;font-size:13px;line-height:1.42;margin:8px 0}.mini.bot{background:#eafff8;color:#132822;border-bottom-left-radius:4px}.mini.user{background:#1d9e75;color:white;margin-left:auto;border-bottom-right-radius:4px}.card{padding:18px;position:relative;overflow:hidden}.card:before,.page-head:before,.builder-main:before,.builder-side:before{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:linear-gradient(135deg,rgba(34,240,183,.16),transparent 38%,rgba(53,167,255,.07));opacity:.9}.card>*,.page-head>*,.builder-main>*,.builder-side>*{position:relative}.stack{display:grid;gap:12px}label{display:block;font-size:13px;font-weight:800;color:#263a35}input,textarea,select{width:100%;margin-top:7px;border:1px solid #9fd3c2;background:rgba(247,255,252,.86);color:var(--text);border-radius:8px;padding:11px 12px;font:inherit}textarea{min-height:94px;resize:vertical}input:focus,textarea:focus,select:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px rgba(29,158,117,.14)}button,.btn{border:1px solid rgba(96,210,177,.55);background:linear-gradient(180deg,rgba(242,255,250,.96),rgba(220,245,237,.9));color:var(--text);border-radius:8px;min-height:40px;padding:10px 14px;font-weight:900;display:inline-flex;align-items:center;justify-content:center;gap:8px;cursor:pointer;box-shadow:0 0 0 1px rgba(34,240,183,.08);transition:.18s ease}.btn.primary,button.primary{background:linear-gradient(135deg,#21b987,#168866);border-color:#45e2b5;color:white;box-shadow:0 0 0 1px rgba(34,240,183,.2),0 0 20px rgba(34,240,183,.18)}hr{border:0;border-top:1px solid var(--line);margin:18px 0}.page-head{padding:22px;margin-bottom:16px;display:flex;justify-content:space-between;gap:16px;align-items:center;position:relative;overflow:hidden}.page-head h1{font-size:32px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}.stats article{background:linear-gradient(135deg,rgba(226,252,244,.94),rgba(208,239,229,.86));border:1px solid rgba(96,210,177,.45);border-radius:10px;padding:18px;box-shadow:0 0 0 1px rgba(34,240,183,.1),0 0 20px rgba(34,240,183,.09)}.stats strong{display:block;font-size:26px}.stats span{color:var(--muted);font-size:13px;font-weight:700}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.agent-card p{color:var(--muted);min-height:70px}.agent-top span{float:right;background:#d9f3eb;color:var(--strong);border-radius:999px;padding:5px 8px;font-size:11px;font-weight:900}.agent-top strong{font-size:20px}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.empty{grid-column:1/-1;background:var(--panel);border:1px dashed var(--line);border-radius:10px;padding:24px;color:var(--muted)}
.landing-hero{display:grid;grid-template-columns:minmax(0,1fr) 430px;gap:26px;align-items:center;min-height:560px;padding:26px 0 34px}.landing-copy{color:#f3fffb}.landing-copy h1{font-size:clamp(38px,4.5vw,56px);line-height:1.04;margin:10px 0 16px;max-width:720px;font-weight:950}.landing-copy p{color:#c6eadf;font-size:16px;line-height:1.65;max-width:650px}.landing-metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:22px;max-width:650px}.landing-metrics article{border:1px solid rgba(101,255,208,.28);background:rgba(8,23,19,.62);border-radius:10px;padding:13px}.landing-metrics strong{display:block;color:#f3fffb;font-size:18px}.landing-metrics span{display:block;color:#a8d8ca;font-size:12px;margin-top:4px}.landing-console{background:linear-gradient(180deg,rgba(16,35,31,.98),rgba(8,18,16,.98));border:1px solid rgba(101,255,208,.34);border-radius:16px;padding:16px;box-shadow:0 0 0 1px rgba(34,240,183,.12),0 0 42px rgba(34,240,183,.16),0 24px 70px rgba(0,0,0,.32)}.console-bar{display:flex;align-items:center;gap:9px;color:#f3fffb;border-bottom:1px solid rgba(148,205,188,.22);padding-bottom:12px}.console-bar span{width:9px;height:9px;border-radius:999px;background:#65ffd0;box-shadow:0 0 16px rgba(34,240,183,.82)}.console-bar em{margin-left:auto;color:#9fe7d3;font-size:12px;font-style:normal;border:1px solid rgba(101,255,208,.25);border-radius:999px;padding:4px 8px}.console-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin:14px 0}.console-stats article{background:rgba(238,255,249,.08);border:1px solid rgba(148,205,188,.18);border-radius:10px;padding:11px}.console-stats strong{display:block;color:#65ffd0;font-size:22px}.console-stats span{display:block;color:#bde7db;font-size:11px;margin-top:3px}.console-feed{display:grid;gap:9px}.console-feed div{background:#edf8f4;color:#10201d;border:1px solid rgba(148,205,188,.4);border-radius:10px;padding:11px}.console-feed b,.console-feed span{display:block}.console-feed span{color:#57706a;font-size:12px;margin-top:4px;line-height:1.35}.landing-section{background:linear-gradient(145deg,rgba(236,252,247,.96),rgba(218,242,234,.9));border:1px solid rgba(96,210,177,.55);border-radius:12px;padding:24px;margin-bottom:16px;box-shadow:0 0 0 1px rgba(34,240,183,.12),0 0 22px rgba(34,240,183,.1),0 18px 50px rgba(5,18,15,.16)}.landing-section h2{font-size:28px;line-height:1.15;margin:8px 0 12px;max-width:760px}.landing-section>p,.landing-section p{color:var(--muted);line-height:1.55}.landing-grid,.channel-cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}.landing-grid article,.channel-cards article{border:1px solid rgba(96,210,177,.38);background:rgba(247,255,252,.82);border-radius:10px;padding:16px}.landing-grid strong{display:inline-grid;place-items:center;min-width:38px;height:30px;border-radius:8px;background:#10231f;color:#65ffd0;font-size:12px}.landing-grid h3,.channel-cards h3{margin:12px 0 8px;font-size:18px}.channels-band,.contact-band{display:grid;grid-template-columns:1fr 1fr;gap:18px;align-items:center}.channel-cards{grid-template-columns:1fr 1fr;margin:0}.channel-cards span{color:var(--strong);font-weight:950;text-transform:uppercase;font-size:12px}.channel-cards strong{display:block;font-size:18px;margin:8px 0}.landing-footer{display:flex;gap:16px;justify-content:center;color:#d9f4eb;margin:24px 0 10px}.legal-page{background:linear-gradient(145deg,rgba(236,252,247,.96),rgba(218,242,234,.9));border:1px solid rgba(96,210,177,.55);border-radius:12px;padding:30px;box-shadow:var(--shadow)}.legal-page h1{font-size:34px;margin:8px 0 14px}.legal-page p{color:var(--muted);line-height:1.7;font-size:16px}
.login-grid{grid-template-columns:minmax(0,1.08fr) minmax(360px,420px);align-items:start;max-width:1120px;margin:0 auto}.login-grid .hero-panel{min-height:0;display:flex;flex-direction:column;justify-content:flex-start;padding:30px 34px}.login-grid .hero-panel h1{font-size:clamp(34px,3.7vw,50px);max-width:760px;margin-bottom:18px}.login-grid .signal-grid{margin:18px 0 16px;grid-template-columns:repeat(3,minmax(0,1fr))}.login-grid .feature-row{margin-top:14px}.login-grid .mini-chat{margin-top:8px}.login-card{align-self:start;position:sticky;top:114px;padding:22px}.login-card h2{margin:0 0 14px}.login-card .stack{gap:10px}.login-card input{min-height:40px}.login-card hr{margin:16px 0}.login-card button{width:100%}
button,.btn,.feature-row span,.pill-row span{transition:box-shadow .18s ease,border-color .18s ease,background .18s ease,transform .18s ease,color .18s ease}
button:hover,.btn:hover,.feature-row span:hover,.pill-row span:hover{border-color:rgba(34,240,183,.95);box-shadow:0 0 0 3px rgba(34,240,183,.14),0 0 22px rgba(34,240,183,.42),inset 0 1px 0 rgba(255,255,255,.22);transform:translateY(-1px)}
.btn.primary:hover,button.primary:hover{background:#20b987;box-shadow:0 0 0 3px rgba(34,240,183,.18),0 0 28px rgba(34,240,183,.52)}
.builder{grid-template-columns:250px 1fr}.builder-side{padding:14px;position:sticky;top:98px;display:grid;gap:8px}.builder-main{padding:22px}.section-title{font-size:18px;font-weight:900;margin:20px 0 12px}.section-help{margin:-4px 0 16px;color:#4d6961;background:rgba(234,255,248,.62);border:1px solid rgba(96,210,177,.34);border-radius:10px;padding:11px 12px;line-height:1.45}.subsection-title{margin:18px 0 10px;color:#0f6e56;font-size:13px;font-weight:900;text-transform:uppercase;letter-spacing:.04em}.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.full{grid-column:1/-1}.knowledge{background:linear-gradient(135deg,rgba(34,240,183,.12),rgba(53,167,255,.07)),#f7fffc;border:1px solid #94cdbc;border-radius:10px;padding:12px}.knowledge textarea{min-height:150px}.quality{margin-top:8px;background:#0f1917;color:#d7fff2;border-radius:10px;padding:14px}.quality strong{font-size:32px}.quality span{display:block;color:#9ed7c5}.quality li{margin:6px 0}.quality .ok{color:#86efac}.quality .bad{color:#f7b4b4}.faq-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}.chat-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow);overflow:hidden}.chat-box{height:520px;overflow:auto;padding:18px;display:flex;flex-direction:column;gap:10px;background:linear-gradient(45deg,rgba(29,158,117,.06) 25%,transparent 25%),#edf8f4}.msg{max-width:82%;padding:11px 13px;border-radius:16px;line-height:1.45}.msg.bot{align-self:flex-start;background:#f7fffc;border-bottom-left-radius:5px}.msg.user{align-self:flex-end;background:var(--green);color:white;border-bottom-right-radius:5px}.chat-form{display:flex;gap:8px;padding:12px;background:#f7fffc;border-top:1px solid var(--line)}.chat-form input{margin:0}pre{white-space:pre-wrap;word-break:break-word;background:#0f1917;color:#b6f3de;border-radius:8px;padding:12px;font-size:12px}table{width:100%;border-collapse:collapse;overflow:hidden}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#e2f2ed}.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#10231f;color:white;border-radius:8px;padding:10px 14px;display:none}.toast.show{display:block}
.control-hero{padding:24px;margin-bottom:16px;border:1px solid rgba(148,205,188,.42);border-radius:14px;background:linear-gradient(115deg,rgba(8,22,19,.92),rgba(14,48,41,.82));color:#f2fffb;display:flex;justify-content:space-between;gap:18px;align-items:center;box-shadow:var(--shadow)}.control-hero h1{font-size:34px;margin:6px 0}.control-hero p{color:#bfe5da}.big-cta{min-height:54px;padding:0 22px;font-size:16px}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:16px}.section-row{display:flex;align-items:center;justify-content:space-between;margin:4px 0 12px}.section-row h2{margin:0}.dash-side{display:grid;gap:14px;align-content:start}.feed-card ul{list-style:none;padding:0;margin:0 0 14px;display:grid;gap:10px}.feed-card li{border:1px solid var(--line);background:#f7fffc;border-radius:10px;padding:10px}.feed-card li strong,.feed-card li span{display:block}.feed-card li span{color:var(--muted);font-size:12px;margin-top:4px}.agent-status{margin-top:8px;display:inline-flex;border-radius:999px;padding:6px 9px;font-size:12px;font-weight:900;background:#e9f5f1;color:#40645b}.agent-status.ready{background:#d9f8ec;color:#0f6e56}.agent-status.active{background:#e8f3ff;color:#265f9f}.agent-status.draft{background:#fff2df;color:#8a5618}.agents-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.filters{display:flex;gap:10px;align-items:center;margin:0 0 14px}.filters select{margin:0;max-width:220px}.lead-table td span{display:block;color:var(--muted);font-size:12px;margin-top:4px}.lead-form{display:grid;gap:8px;min-width:240px}.lead-form select,.lead-form textarea{margin:0}.lead-form textarea{min-height:64px}.intent-pill{display:inline-flex!important;background:#e1f5ee;color:#0f6e56;border:1px solid #9dd8c4;border-radius:999px;padding:5px 8px;font-weight:900}.conversation-detail{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:16px}
.sales-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px}.funnel-card{display:grid;gap:10px}.funnel-card div{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:#f7fffc;padding:10px 12px;display:flex;justify-content:space-between;align-items:center}.funnel-card div>*{position:relative;z-index:1}.funnel-card i{position:absolute;left:0;top:0;bottom:0;background:linear-gradient(90deg,rgba(34,240,183,.26),rgba(53,167,255,.12));z-index:0}.priority{display:inline-flex;border-radius:999px;padding:6px 9px;font-size:12px;font-weight:900;border:1px solid var(--line);background:#eef7f4;color:#40645b}.priority.hot{background:#d9f8ec;color:#0f6e56;border-color:#93dcc5}.priority.warm{background:#fff2df;color:#8a5618;border-color:#f3c98f}.priority.cold{background:#eef3f7;color:#536775}.smart-summary h2{margin-bottom:8px}.widget-editor{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:14px;align-items:start;border:1px solid var(--line);background:#f7fffc;border-radius:12px;padding:14px}.widget-preview{min-height:420px;position:relative;border-radius:12px;overflow:hidden;background:linear-gradient(90deg,rgba(34,240,183,.12) 1px,transparent 1px),linear-gradient(0deg,rgba(53,167,255,.1) 1px,transparent 1px),#10231f;background-size:34px 34px;color:#10201d}.widget-preview #previewFab{position:absolute;right:20px;bottom:20px;min-width:58px;height:58px;border-radius:999px;border:0;background:#1d9e75;color:white;font-weight:900;padding:0 16px;box-shadow:0 0 0 5px rgba(29,158,117,.22),0 14px 38px rgba(0,0,0,.32)}.preview-panel{position:absolute;right:20px;bottom:92px;width:min(340px,calc(100% - 40px));height:300px;background:#f2fbf8;border:1px solid #aecac1;border-radius:14px;box-shadow:0 18px 48px rgba(0,0,0,.24);overflow:hidden}.preview-panel header{background:#10231f;color:white;padding:12px 14px;display:flex;justify-content:space-between}.preview-messages{height:190px;padding:12px;background:#edf8f4;display:flex;flex-direction:column;gap:8px}.preview-messages p{max-width:86%;margin:0;background:white;border-radius:14px;border-bottom-left-radius:4px;padding:10px 12px;font-size:13px}.preview-messages .preview-user{align-self:flex-end;background:#1d9e75;color:white;border-bottom-left-radius:14px;border-bottom-right-radius:4px}.preview-panel form{display:flex;gap:8px;padding:10px;background:white}.preview-panel input{margin:0}.preview-panel button{min-height:38px;background:#1d9e75;color:white;border-color:#1d9e75}
.crm-layout{display:grid;grid-template-columns:280px minmax(0,1fr) 300px;gap:14px;align-items:start}.crm-list{display:grid;gap:8px}.inbox-item{display:block;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;box-shadow:var(--shadow)}.inbox-item.active{border-color:var(--green);box-shadow:0 0 0 3px rgba(29,158,117,.13),var(--shadow)}.inbox-item strong,.inbox-item span,.inbox-item small{display:block}.inbox-item span{color:var(--strong);font-weight:800;font-size:13px;margin-top:5px}.inbox-item small{color:var(--muted);margin-top:4px}.crm-side{display:grid;gap:10px}.public-agent{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:16px;align-items:start;background:linear-gradient(135deg,rgba(8,22,19,.92),rgba(14,48,41,.84));color:#f2fffb;border:1px solid rgba(148,205,188,.42);border-radius:14px;padding:28px;box-shadow:var(--shadow)}.public-agent h1{font-size:42px;line-height:1.05;margin:8px 0 14px}.public-agent p{color:#c5eadf;line-height:1.6}.link-bio{min-height:calc(100vh - 150px);display:grid;place-items:center;padding:22px 0}.bio-shell{width:min(560px,100%);background:linear-gradient(145deg,rgba(237,254,248,.96),rgba(205,242,231,.92));border:1px solid rgba(84,224,183,.65);box-shadow:0 0 0 1px rgba(34,240,183,.18),0 0 46px rgba(34,240,183,.2),0 24px 70px rgba(0,0,0,.26);border-radius:18px;padding:26px;display:grid;gap:14px;text-align:center}.bio-avatar{width:74px;height:74px;margin:0 auto;border-radius:20px;background:linear-gradient(135deg,#10352d,#1eb987);display:grid;place-items:center;color:#f2fffb;font-size:24px;font-weight:950;box-shadow:0 0 0 6px rgba(34,240,183,.14),0 0 34px rgba(34,240,183,.25)}.bio-shell h1{font-size:34px;line-height:1.05;margin:0}.bio-shell p{margin:0;color:var(--muted);line-height:1.55}.bio-tags{display:flex;flex-wrap:wrap;gap:8px;justify-content:center}.bio-tags span{border:1px solid rgba(72,184,151,.5);background:rgba(244,255,251,.76);border-radius:999px;padding:7px 10px;font-size:12px;font-weight:850;color:#17644f}.bio-actions{display:grid;gap:10px;margin-top:4px}.bio-link{display:block;text-align:left;text-decoration:none;background:rgba(247,255,252,.9);border:1px solid rgba(95,190,162,.58);border-radius:12px;padding:14px 15px;color:var(--ink);box-shadow:0 10px 24px rgba(0,0,0,.08);transition:.18s ease}.bio-link:hover{transform:translateY(-1px);border-color:rgba(34,240,183,.9);box-shadow:0 0 0 4px rgba(34,240,183,.12),0 0 28px rgba(34,240,183,.2),0 16px 32px rgba(0,0,0,.12)}.bio-link strong,.bio-link span{display:block}.bio-link span{font-size:13px;color:var(--muted);margin-top:3px}.bio-link.primary{background:linear-gradient(135deg,#1ba676,#148460);color:white;border-color:#39e2ac}.bio-link.primary span{color:#d9fff2}.pricing-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px}.pricing-card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;box-shadow:var(--shadow);display:grid;gap:10px}.pricing-card.active{border-color:var(--green);box-shadow:0 0 0 3px rgba(29,158,117,.13),var(--shadow)}.pricing-card>span{font-size:12px;font-weight:900;color:var(--strong);text-transform:uppercase}.pricing-card strong{font-size:36px}.pricing-card small{font-size:14px;color:var(--muted)}.pricing-card ul{margin:0;padding-left:18px;color:var(--muted)}
.pricing-card{background:linear-gradient(145deg,rgba(236,252,247,.96),rgba(217,243,234,.9));border-color:rgba(96,210,177,.5);box-shadow:0 0 0 1px rgba(34,240,183,.13),0 0 28px rgba(34,240,183,.1),0 18px 52px rgba(5,18,15,.16);position:relative;overflow:hidden;transition:.18s ease}.pricing-card:before{content:"";position:absolute;inset:0;background:linear-gradient(135deg,rgba(34,240,183,.18),transparent 42%,rgba(53,167,255,.08));pointer-events:none}.pricing-card>*{position:relative}.pricing-card:hover{transform:translateY(-2px);border-color:rgba(34,240,183,.8);box-shadow:0 0 0 1px rgba(34,240,183,.24),0 0 34px rgba(34,240,183,.2),0 22px 60px rgba(5,18,15,.18)}.pricing-card.active{border-color:#48e6bb;box-shadow:0 0 0 2px rgba(34,240,183,.22),0 0 34px rgba(34,240,183,.23),0 22px 60px rgba(5,18,15,.18)}
.platform-assistant{position:fixed;right:22px;bottom:22px;z-index:99999;font-family:Inter,system-ui,sans-serif}.assistant-fab{min-width:72px;height:48px;border-radius:999px;border:1px solid rgba(101,255,208,.72);background:linear-gradient(135deg,#21b987,#147457);color:white;font-weight:950;box-shadow:0 0 0 5px rgba(34,240,183,.14),0 0 30px rgba(34,240,183,.32),0 16px 44px rgba(0,0,0,.28)}.assistant-panel{width:min(380px,calc(100vw - 32px));background:linear-gradient(145deg,rgba(237,254,248,.98),rgba(216,244,235,.96));border:1px solid rgba(96,210,177,.68);border-radius:14px;box-shadow:0 0 0 1px rgba(34,240,183,.18),0 0 36px rgba(34,240,183,.22),0 24px 70px rgba(0,0,0,.3);overflow:hidden}.assistant-panel header{background:#10231f;color:#f3fffb;padding:13px 14px;display:flex;align-items:center;justify-content:space-between;gap:12px}.assistant-panel header span{display:block;color:#aee8d7;font-size:12px;margin-top:3px}.assistant-panel header button{background:transparent;border:0;color:white;font-size:24px;cursor:pointer}.assistant-messages{height:280px;overflow:auto;padding:14px;display:flex;flex-direction:column;gap:9px;background:linear-gradient(90deg,rgba(34,240,183,.08) 1px,transparent 1px),linear-gradient(0deg,rgba(53,167,255,.06) 1px,transparent 1px),#edf8f4;background-size:30px 30px}.assistant-messages p{margin:0;max-width:88%;padding:10px 12px;border-radius:14px;line-height:1.45;font-size:14px}.assistant-messages .bot{align-self:flex-start;background:white;color:#10201d;border-bottom-left-radius:4px}.assistant-messages .user{align-self:flex-end;background:#1d9e75;color:white;border-bottom-right-radius:4px}.assistant-messages .action{background:transparent;padding:0}.assistant-messages .action button{min-height:36px;background:#1d9e75;color:white;border-color:#1d9e75;box-shadow:0 0 18px rgba(34,240,183,.2)}.assistant-quick{display:flex;gap:7px;flex-wrap:wrap;padding:10px;background:#f7fffc;border-top:1px solid rgba(150,210,192,.55)}.assistant-quick button{min-height:32px;padding:7px 9px;font-size:12px}.assistant-panel form{display:flex;gap:8px;padding:10px;background:white;border-top:1px solid rgba(150,210,192,.55)}.assistant-panel input{margin:0;min-height:40px}.assistant-panel form button{min-height:40px;background:#1d9e75;color:white;border-color:#1d9e75}
.wizard-tabs{display:flex;gap:6px;overflow:auto;padding-bottom:10px;border-bottom:1px solid var(--line);margin-bottom:16px}.wizard-tabs button{white-space:nowrap;min-height:34px;padding:7px 10px;border-radius:999px;background:#edf8f4}.wizard-tabs button.active{background:var(--green);border-color:var(--green);color:white}.wizard-step{display:none}.wizard-step.active{display:block}.wizard-actions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:18px;padding-top:14px;border-top:1px solid var(--line)}.side-label{margin:0 0 4px;color:var(--muted);font-size:12px;font-weight:900;text-transform:uppercase}.ai-review{display:flex;align-items:center;gap:10px;margin:10px 0 14px}.ai-review span,.hint-line{color:var(--muted);font-size:13px}.improve-result{display:none;border:1px solid #94cdbc;border-radius:10px;background:#f7fffc;padding:12px;margin-bottom:14px}.improve-result.show{display:block}.improve-result h3{margin:0 0 8px}.improve-result ul{margin:8px 0;padding-left:20px}.improve-result textarea{min-height:150px}.final-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.final-grid article{border:1px solid var(--line);background:#f7fffc;border-radius:10px;padding:14px}.final-grid strong{display:block;font-size:24px}.final-grid span{color:var(--muted);font-size:13px}
.infra-map{position:relative;min-height:430px;margin-top:18px;border:1px solid rgba(63,210,168,.48);border-radius:18px;overflow:hidden;background:radial-gradient(circle at 50% 50%,rgba(34,240,183,.34),transparent 26%),linear-gradient(90deg,rgba(34,240,183,.16) 1px,transparent 1px),linear-gradient(0deg,rgba(53,167,255,.1) 1px,transparent 1px),linear-gradient(135deg,#071512,#102b25 58%,#06120f);background-size:auto,34px 34px,34px 34px,auto;box-shadow:inset 0 0 70px rgba(34,240,183,.15),0 0 44px rgba(34,240,183,.18)}.infra-map:before,.infra-map:after{content:"";position:absolute;inset:56px;border:1px solid rgba(101,255,208,.22);border-radius:28px;box-shadow:0 0 34px rgba(34,240,183,.13)}.infra-map:after{inset:104px;border-color:rgba(53,167,255,.18);transform:rotate(-2deg)}.infra-core{position:absolute;left:50%;top:50%;width:260px;min-height:150px;transform:translate(-50%,-50%);display:grid;place-items:center;text-align:center;padding:22px;border-radius:26px;background:linear-gradient(145deg,rgba(15,50,42,.96),rgba(7,22,19,.98));border:1px solid rgba(101,255,208,.55);color:#edfff9;box-shadow:0 0 0 8px rgba(34,240,183,.07),0 0 54px rgba(34,240,183,.34),0 24px 70px rgba(0,0,0,.34);z-index:3}.infra-core span{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;background:#65ffd0;color:#08201a;font-weight:950;box-shadow:0 0 28px rgba(34,240,183,.72)}.infra-core strong{font-size:22px}.infra-core small{color:#a7ddcf;line-height:1.35}.infra-node{position:absolute;width:250px;padding:16px;border-radius:16px;background:linear-gradient(145deg,rgba(238,255,249,.96),rgba(195,237,224,.9));border:1px solid rgba(101,255,208,.58);box-shadow:0 0 0 1px rgba(34,240,183,.16),0 0 32px rgba(34,240,183,.18),0 18px 44px rgba(0,0,0,.22);z-index:2}.infra-node:before{content:"";position:absolute;width:120px;height:1px;background:linear-gradient(90deg,transparent,rgba(101,255,208,.9),transparent);box-shadow:0 0 16px rgba(34,240,183,.8)}.infra-node span{display:inline-flex;border-radius:999px;border:1px solid rgba(29,158,117,.38);background:#0f2b24;color:#65ffd0;padding:5px 8px;font-weight:950;font-size:12px}.infra-node strong{display:block;margin-top:9px;font-size:18px}.infra-node p{margin:6px 0 0;color:#48645d;font-size:13px}.infra-node.n1{left:34px;top:36px}.infra-node.n1:before{right:-112px;top:52px;transform:rotate(18deg)}.infra-node.n2{right:34px;top:48px}.infra-node.n2:before{left:-112px;top:58px;transform:rotate(-18deg)}.infra-node.n3{left:54px;bottom:42px}.infra-node.n3:before{right:-108px;top:28px;transform:rotate(-20deg)}.infra-node.n4{right:54px;bottom:40px}.infra-node.n4:before{left:-108px;top:30px;transform:rotate(20deg)}
.bg-grid{background:radial-gradient(900px 520px at 50% -120px,rgba(51,255,190,.45),transparent 62%),radial-gradient(760px 460px at 12% 12%,rgba(11,90,69,.55),transparent 58%),radial-gradient(760px 520px at 86% 8%,rgba(23,137,101,.38),transparent 58%),linear-gradient(180deg,#06110f 0%,#0d2f27 235px,#163c34 390px,#eaf3ef 700px,#f5f7f6 100%);background-size:auto!important}.topbar,.control-hero,.hero-panel,.landing-console,.infra-map{background:radial-gradient(580px 220px at 50% -35%,rgba(110,255,209,.34),transparent 62%),linear-gradient(145deg,#07211c 0%,#0e3a31 42%,#061410 100%)!important;border-color:rgba(133,255,218,.42)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.16),inset 0 -24px 60px rgba(0,0,0,.22),0 0 0 1px rgba(34,240,183,.16),0 0 46px rgba(34,240,183,.18),0 24px 70px rgba(0,0,0,.28)!important}.hero-panel:before,.landing-section:before,.infra-map:before,.infra-map:after{display:none!important}.card,.page-head,.builder-main,.builder-side,table,.landing-section,.pricing-card,.stats article,.feed-card li,.funnel-card div,.widget-editor,.chat-card,.login-card{background:radial-gradient(420px 150px at 50% -28px,rgba(107,255,210,.22),transparent 60%),linear-gradient(145deg,rgba(238,255,249,.97),rgba(202,235,224,.93))!important;border-color:rgba(94,211,174,.48)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.72),inset 0 -18px 40px rgba(12,66,52,.08),0 0 0 1px rgba(34,240,183,.1),0 18px 48px rgba(5,30,23,.16)!important}.card:before,.page-head:before,.builder-main:before,.builder-side:before,.pricing-card:before{background:radial-gradient(260px 90px at 24% 0%,rgba(255,255,255,.45),transparent 62%)!important;opacity:1!important}.infra-core{background:radial-gradient(190px 84px at 50% -10%,rgba(122,255,215,.48),transparent 70%),linear-gradient(145deg,#0c3b31,#061511)!important}.infra-node,.channel-cards article,.landing-metrics article,.console-stats article,.console-feed div{background:radial-gradient(260px 86px at 50% -18px,rgba(111,255,209,.28),transparent 66%),linear-gradient(145deg,rgba(236,255,248,.96),rgba(188,230,216,.92))!important;border-color:rgba(95,225,184,.5)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.66),0 12px 34px rgba(5,30,23,.15),0 0 24px rgba(34,240,183,.12)!important}.infra-node:before,.assistant-messages,.widget-preview,.chat-box{background:radial-gradient(520px 190px at 50% 0%,rgba(105,255,210,.26),transparent 65%),linear-gradient(145deg,#eaf9f4,#d6eee6)!important;background-size:auto!important}.preview-messages{background:linear-gradient(145deg,#eaf9f4,#d8eee7)!important}.funnel-card i{background:linear-gradient(90deg,rgba(34,240,183,.42),rgba(34,240,183,.12))!important}
.topbar,.topbar a,.brand,.nav-pill,.control-hero,.control-hero h1,.control-hero p,.hero-panel,.hero-panel h1,.hero-panel p,.landing-copy,.landing-copy h1,.landing-copy p,.landing-console,.infra-map,.infra-core{color:#f6fffb!important}.brand small,.hero-panel .hero-copy,.landing-copy p,.control-hero p,.console-bar em,.console-feed span,.landing-metrics span,.console-stats span,.infra-core small{color:#d5f7ec!important}.nav-pill{color:#effff9!important;background:rgba(255,255,255,.08)!important;border-color:rgba(185,255,232,.28)!important}.nav-pill:hover,.nav-pill.active{color:#ffffff!important;background:rgba(101,255,208,.18)!important;border-color:rgba(137,255,220,.6)!important}.card,.page-head,.builder-main,.builder-side,table,.landing-section,.pricing-card,.stats article,.feed-card li,.funnel-card div,.widget-editor,.chat-card,.login-card,.infra-node,.channel-cards article,.console-feed div{color:#10201d!important}.card p,.page-head p,.landing-section p,.pricing-card p,.feed-card li span,.stats span,.agent-card p,.hint-line,.ai-review span,.lead-table td span,.bio-shell p,.bio-link span,.console-feed div span,.infra-node p,.channel-cards p{color:#405d55!important}.landing-section h2,.landing-section h3,.card h2,.card h3,.page-head h1,.builder-main h1,.builder-main h2,.pricing-card h3,.pricing-card strong,.stats strong,.feed-card li strong,.infra-node strong,.channel-cards strong,.console-feed div b{color:#0b201b!important}.eyebrow,.section-title,.subsection-title,.side-label{color:#087456!important}.hero-panel .eyebrow,.landing-copy .eyebrow{color:#7dffda!important}.landing-metrics article strong,.console-stats strong{color:#062119!important}.landing-metrics article span,.console-stats span{color:#17483b!important}.infra-core strong,.infra-core small{color:#f7fffc!important}.infra-node span{color:#dffff5!important;background:#0b3028!important}.quality,.quality span,.quality li{color:#eafff6!important}.assistant-panel header,.assistant-panel header span{color:#f7fffc!important}.assistant-messages .bot{color:#10201d!important}.assistant-messages .user{color:#fff!important}
.card,.page-head,.builder-main,.builder-side,table,.landing-section,.pricing-card,.stats article,.feed-card li,.funnel-card div,.widget-editor,.chat-card,.login-card,.infra-node,.channel-cards article,.console-feed div,.bio-shell,.bio-link,.assistant-panel,.assistant-quick,.assistant-panel form{background:radial-gradient(420px 150px at 50% -28px,rgba(93,255,204,.30),transparent 62%),linear-gradient(145deg,rgba(218,246,236,.96),rgba(178,226,210,.92))!important;border-color:rgba(70,220,174,.62)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.58),inset 0 -18px 42px rgba(10,80,59,.12),0 0 0 1px rgba(34,240,183,.18),0 0 34px rgba(34,240,183,.40),0 18px 48px rgba(5,30,23,.16)!important}.stats article,.pricing-card,.landing-section,.card{background-color:rgba(205,242,229,.94)!important}
.landing-copy p,.hero-panel .hero-copy,.control-hero p{color:#ecfff8!important;font-weight:650!important}.brand small,.nav-pill,.landing-footer a{color:#eafff7!important;font-weight:850!important}.landing-metrics span,.console-stats span,.console-feed span,.phone-top,.mini-top{color:#073529!important;font-weight:850!important}.landing-section p,.channel-cards p,.pricing-card p,.pricing-card small,.stats span,.feed-card li span,.agent-card p,.pill-row span,.agent-status,.funnel-card span,.lead-table td span,.hint-line,.ai-review span,.section-help,.bio-link span,.bio-shell p,.infra-node p{color:#173f35!important;font-weight:750!important}.eyebrow,.side-label,.subsection-title{color:#045f47!important;font-weight:950!important}.landing-section .eyebrow,.page-head .eyebrow,.control-hero .eyebrow{color:#035e47!important}.landing-copy .eyebrow,.hero-panel .eyebrow{color:#a8ffe7!important;text-shadow:0 0 18px rgba(34,240,183,.24)}.stats strong,.feed-card li strong,.agent-top strong,.section-row h2,.sales-grid h2,.dash-side h2,.landing-section h2,.landing-section h3,.pricing-card h3,.pricing-card strong,.infra-node strong,.channel-cards strong{color:#061c17!important}.quality span,.quality li{color:#eafff7!important;font-weight:800!important}.lead-form textarea,.lead-form select,input,textarea,select{color:#0b211b!important}.intent-pill,.priority,.agent-status{color:#063b2d!important}
button,.btn,.nav-pill{background:radial-gradient(160px 70px at 50% -22px,rgba(134,255,219,.48),transparent 70%),linear-gradient(145deg,#1fc28e,#0d7e5c)!important;border-color:rgba(132,255,218,.72)!important;color:#f8fffc!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.32),inset 0 -12px 24px rgba(0,40,28,.22),0 0 0 1px rgba(34,240,183,.22),0 0 28px rgba(34,240,183,.40),0 12px 28px rgba(3,32,24,.22)!important;text-shadow:0 1px 0 rgba(0,0,0,.16)}button:hover,.btn:hover,.nav-pill:hover,.nav-pill.active{background:radial-gradient(180px 78px at 50% -24px,rgba(170,255,231,.58),transparent 72%),linear-gradient(145deg,#27d9a0,#10946c)!important;border-color:rgba(177,255,232,.9)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.42),inset 0 -12px 24px rgba(0,48,33,.2),0 0 0 2px rgba(34,240,183,.24),0 0 38px rgba(34,240,183,.58),0 16px 34px rgba(3,32,24,.26)!important}.btn.primary,button.primary,.big-cta{background:radial-gradient(180px 78px at 50% -24px,rgba(178,255,234,.62),transparent 72%),linear-gradient(145deg,#28d59e,#0a7657)!important;color:#ffffff!important;border-color:rgba(178,255,232,.92)!important}.actions .btn:not(.primary),.wizard-actions .btn:not(.primary),.chat-form .btn:not(.primary){background:radial-gradient(160px 70px at 50% -22px,rgba(121,255,211,.42),transparent 70%),linear-gradient(145deg,#21bd8c,#0f7658)!important;color:#f8fffc!important;border-color:rgba(132,255,218,.72)!important}.pricing-card.active,.agent-card:hover,.feed-card li:hover,.stats article:hover,.landing-section:hover,.card:hover{border-color:rgba(119,255,213,.82)!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.6),inset 0 -18px 42px rgba(10,80,59,.12),0 0 0 1px rgba(34,240,183,.24),0 0 42px rgba(34,240,183,.40),0 22px 58px rgba(5,30,23,.18)!important}
.mini.bot,.msg.bot,.preview-messages p,.assistant-messages .bot{background:#e8fff6!important;color:#0b211b!important;font-weight:750!important;text-shadow:none!important}.mini.user,.msg.user,.preview-messages .preview-user,.assistant-messages .user{background:linear-gradient(145deg,#20ba87,#0d7f5e)!important;color:#ffffff!important;font-weight:800!important;text-shadow:0 1px 0 rgba(0,0,0,.18)!important}.mini-chat .mini-top{color:#71ffd4!important}.mini-chat .mini-top span{background:#35f3bd!important}
@media(max-width:900px){.auth-grid,.chat-layout,.builder,.login-grid,.dashboard-grid,.conversation-detail,.sales-grid,.widget-editor,.crm-layout,.public-agent,.pricing-grid,.landing-hero,.landing-grid,.channels-band,.contact-band,.channel-cards{grid-template-columns:1fr}.grid,.stats,.form-grid,.agents-grid,.final-grid{grid-template-columns:1fr}.builder-side{position:static}.topbar,.page-head,.control-hero,.filters{flex-direction:column;align-items:flex-start}.hero-panel h1{font-size:32px}.login-grid .hero-panel{min-height:0;padding:24px}.login-grid .hero-panel h1{font-size:32px}.login-grid .signal-grid{grid-template-columns:1fr;gap:8px}.login-grid .mini-chat{display:none}.login-card{position:static;padding:18px}.bio-shell{border-radius:14px;padding:20px}.bio-shell h1{font-size:28px}.landing-hero{min-height:0;padding:18px 0}.landing-copy h1{font-size:42px}.landing-phone{border-radius:18px}.landing-section h2{font-size:28px}}
@media(max-width:900px){.infra-map{min-height:auto;display:grid;gap:12px;padding:16px}.infra-map:before,.infra-map:after,.infra-node:before{display:none}.infra-core,.infra-node{position:relative;left:auto!important;right:auto!important;top:auto!important;bottom:auto!important;width:100%;transform:none}.infra-core{min-height:130px}.landing-metrics{grid-template-columns:1fr}}
"""


JS = r"""
const templates={
  veterinaria:{business_type:'Veterinaria',country_market:'Chile',currency:'CLP',business_name:'Veterinaria Pelitos',city:'Santiago, Chile',hours:'Lunes a sábado de 9:00 a 19:00',knowledge:'Veterinaria para mascotas pequeñas. El vendedor IA debe preguntar nombre del cliente, nombre de la mascota, especie, edad y motivo de consulta. Puede explicar servicios, horarios, vacunas y grooming. Para urgencias, síntomas graves, diagnósticos o tratamientos debe derivar a WhatsApp. No debe inventar precios si no están escritos. Debe invitar a reservar cuando el cliente muestre intención de atención.',services:'Consultas médicas, vacunación, baño y corte, esterilizaciones, alimentos premium y antiparasitarios.',bot_name:'Luna',tone:'empático y paciente',formality:'cercano y respetuoso',local_vocabulary:'Español chileno suave: cotizar, agendar, al tiro solo si encaja. Sin exagerar modismos.',forbidden_vocabulary:'No garabatos, no diagnósticos sin evaluación, no prometer tratamientos.',sales_mission:'Entender qué necesita el cliente, pedir datos básicos de la mascota, explicar servicios y llevar la conversación hacia reserva o WhatsApp.',whatsapp:'+56 9 1234 5678',widget_title:'Luna de Veterinaria Pelitos',widget_label:'Ayuda',widget_welcome:'Hola, soy Luna. Cuéntame qué necesita tu mascota y te ayudo a avanzar.'},
  restaurante:{business_type:'Restaurante / Cafetería',country_market:'México',currency:'MXN',business_name:'La Mesa Viva',knowledge:'Restaurante familiar. El vendedor IA debe responder sobre menú, horarios, reservas, delivery, eventos y promociones vigentes. Debe pedir fecha, hora y cantidad de personas para reservas. Si preguntan por alergias, debe recomendar confirmar con el equipo.',services:'Menú ejecutivo, carta, reservas, delivery, eventos privados y catering.',bot_name:'Sofía',tone:'amigable y cercano',sales_mission:'Ayudar a reservar, recomendar platos y derivar a WhatsApp para confirmar disponibilidad.',widget_title:'Reservas La Mesa Viva',widget_label:'Mesa',widget_welcome:'Hola, te ayudo con menú, reservas o delivery. ¿Qué necesitas hoy?'},
  tienda:{business_type:'Tienda online',country_market:'Colombia',currency:'COP',business_name:'Urban Market',knowledge:'Tienda online. El vendedor IA debe ayudar a encontrar productos, explicar envíos, cambios, garantías y medios de pago. Debe pedir ciudad y producto de interés para cotizar envío.',services:'Ropa urbana, accesorios, envíos nacionales, cambios por talla.',bot_name:'Nico',tone:'juvenil y dinámico',sales_mission:'Guiar al cliente hacia el producto correcto, resolver objeciones de envío/talla y cerrar por WhatsApp o web.',widget_title:'Nico de Urban Market',widget_label:'Comprar',widget_welcome:'Hola, dime qué producto buscas y te ayudo con talla, envío o compra.'},
  barberia:{business_type:'Barbería / Spa',country_market:'Perú',currency:'PEN',business_name:'Studio Corte',knowledge:'Barbería y spa masculino. El vendedor IA debe explicar servicios, duración aproximada, horarios y ayudar a agendar. Debe pedir servicio, día, hora preferida y nombre.',services:'Corte, barba, perfilado, limpieza facial, paquetes premium.',bot_name:'Mateo',tone:'profesional y confiable',sales_mission:'Convertir consultas en reservas, explicar paquetes y pedir datos para agendar.',widget_title:'Agenda Studio Corte',widget_label:'Agenda',widget_welcome:'Hola, te ayudo a elegir servicio y buscar una hora disponible.'},
  inmobiliaria:{business_type:'Inmobiliaria',country_market:'Argentina',currency:'USD',business_name:'Nexo Propiedades',knowledge:'Inmobiliaria. El vendedor IA debe filtrar clientes por operación, presupuesto, zona, tipo de propiedad, dormitorios y fecha estimada. No debe prometer disponibilidad sin confirmación.',services:'Venta, arriendo/alquiler, tasación, visitas y asesoría inmobiliaria.',bot_name:'Valentina',tone:'formal y respetuoso',sales_mission:'Calificar interesados, responder dudas y coordinar visita con un asesor humano.',widget_title:'Valentina Propiedades',widget_label:'Asesoría',widget_welcome:'Hola, cuéntame qué propiedad buscas o quieres publicar y te ayudo a filtrar.'},
  clinica:{business_type:'Clínica estética',country_market:'Chile',currency:'CLP',business_name:'Aura Clínica',knowledge:'Clínica estética. El vendedor IA debe explicar tratamientos de forma general, pedir objetivo del cliente y derivar a evaluación. No debe diagnosticar ni prometer resultados médicos.',services:'Limpieza facial, depilación láser, botox, ácido hialurónico, evaluación estética.',bot_name:'Emma',tone:'empático y paciente',sales_mission:'Orientar con respeto, resolver dudas generales y llevar a evaluación o WhatsApp.',widget_title:'Emma de Aura Clínica',widget_label:'Consulta',widget_welcome:'Hola, te oriento con información general y te ayudo a pedir evaluación.'}
};
function applyTemplate(key){const t=templates[key];Object.entries(t).forEach(([k,v])=>{const el=document.getElementById(k);if(el)el.value=v});updateWidgetPreview();toast('Plantilla aplicada')}
function addFaq(){toast('Hay 6 espacios de preguntas frecuentes listos para completar')}
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),1600)}
function copyText(text){if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(()=>toast('Copiado')).catch(()=>fallbackCopy(text));return}fallbackCopy(text)}
function fallbackCopy(text){const area=document.createElement('textarea');area.value=text;area.style.position='fixed';area.style.left='-9999px';document.body.appendChild(area);area.focus();area.select();try{document.execCommand('copy');toast('Copiado')}catch(e){toast('No se pudo copiar. Selecciona el texto manualmente.')}area.remove()}
function togglePlatformAssistant(){const panel=document.querySelector('#platformAssistant .assistant-panel');const fab=document.querySelector('#platformAssistant .assistant-fab');if(!panel||!fab)return;const open=panel.hidden;panel.hidden=!open;fab.hidden=open;if(open)setTimeout(()=>document.getElementById('assistantInput')?.focus(),60)}
function addAssistantMsg(role,text){const box=document.getElementById('assistantMessages');if(!box)return null;const p=document.createElement('p');p.className=role;p.textContent=text;box.appendChild(p);box.scrollTop=box.scrollHeight;return p}
function addAssistantAction(action){const box=document.getElementById('assistantMessages');if(!box||!action||!action.url)return;const wrap=document.createElement('p');wrap.className='bot action';const btn=document.createElement('button');btn.type='button';btn.textContent=action.label||'Ir ahora';btn.onclick=()=>{location.href=action.url};wrap.appendChild(btn);box.appendChild(wrap);box.scrollTop=box.scrollHeight}
function askPlatformAssistant(text){const input=document.getElementById('assistantInput');if(input){input.value=text;sendPlatformAssistant(new Event('submit'))}}
async function sendPlatformAssistant(event){event.preventDefault();const input=document.getElementById('assistantInput');const text=(input?.value||'').trim();if(!text)return;if(input)input.value='';addAssistantMsg('user',text);const pending=addAssistantMsg('bot','Revisando...');try{const res=await fetch('/api/platform-help',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:text,path:location.pathname})});const data=await res.json();pending.textContent=data.reply||'No pude responder ahora, pero puedo orientarte si reformulas la pregunta.';if(data.action&&data.action.url&&data.action.url!==location.pathname){addAssistantAction(data.action);if(data.action.navigate)setTimeout(()=>{location.href=data.action.url},900)}}catch(e){pending.textContent='No pude conectar con la ayuda en este momento. Prueba de nuevo en unos segundos.'}}
let wizardStep=1;
function setWizardStep(n){wizardStep=Math.max(1,Math.min(6,n));document.querySelectorAll('.wizard-step').forEach(s=>s.classList.toggle('active',Number(s.dataset.step)===wizardStep));document.querySelectorAll('#wizardTabs button').forEach(b=>b.classList.toggle('active',Number(b.dataset.wizard)===wizardStep));const st=document.getElementById('wizardStatus');if(st)st.textContent=`Paso ${wizardStep} de 6`}
function wizardNext(){setWizardStep(wizardStep+1)}
function wizardPrev(){setWizardStep(wizardStep-1)}
document.addEventListener('click',e=>{const b=e.target.closest('#wizardTabs button');if(b)setWizardStep(Number(b.dataset.wizard))});
function formValue(id){const el=document.getElementById(id);return el?el.value:''}
function updateWidgetPreview(){const color=formValue('widget_color')||'#1d9e75';const title=formValue('widget_title')||formValue('bot_name')||'Asistente de ventas';const label=formValue('widget_label')||'IA';const welcome=formValue('widget_welcome')||'Hola, cuéntame qué necesitas y te ayudo a avanzar.';const fab=document.getElementById('previewFab');const titleEl=document.getElementById('previewTitle');const welcomeEl=document.getElementById('previewWelcome');const user=document.querySelector('.preview-user');const send=document.querySelector('.preview-panel button');if(fab){fab.textContent=label;fab.style.background=color;fab.style.boxShadow=`0 0 0 5px ${color}38,0 14px 38px rgba(0,0,0,.32)`}if(titleEl)titleEl.textContent=title;if(welcomeEl)welcomeEl.textContent=welcome;if(user)user.style.background=color;if(send){send.style.background=color;send.style.borderColor=color}}
document.addEventListener('input',e=>{if(['widget_color','widget_title','widget_label','widget_welcome','bot_name'].includes(e.target.id))updateWidgetPreview()});
document.addEventListener('DOMContentLoaded',updateWidgetPreview);
async function improveKnowledge(){const box=document.getElementById('improveResult');if(!box)return;box.classList.add('show');box.innerHTML='<strong>Revisando la base de conocimiento...</strong>';const payload={business_name:formValue('business_name'),business_type:formValue('business_type'),country_market:formValue('country_market'),services:formValue('services'),sales_mission:formValue('sales_mission'),whatsapp:formValue('whatsapp'),knowledge:formValue('knowledge'),groq_model:formValue('groq_model')};const res=await fetch('/api/improve-knowledge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await res.json();box.innerHTML=`<h3>Revisión IA</h3><strong>Qué falta</strong><ul>${(data.missing||[]).map(x=>`<li>${x}</li>`).join('')}</ul><strong>Qué mejorar</strong><ul>${(data.suggestions||[]).map(x=>`<li>${x}</li>`).join('')}</ul><strong>Preguntas que deberías responder</strong><ul>${(data.questions||[]).map(x=>`<li>${x}</li>`).join('')}</ul><label>Versión mejorada<textarea id="improvedKnowledgeText">${data.improved||''}</textarea></label><button type="button" class="btn primary" onclick="document.getElementById('knowledge').value=document.getElementById('improvedKnowledgeText').value;toast('Base de conocimiento actualizada')">Usar esta versión</button>`}
let chatMessages=[];let conversationId=null;
function addMsg(role,text){const chat=document.getElementById('chat');const div=document.createElement('div');div.className='msg '+role;div.textContent=text;chat.appendChild(div);chat.scrollTop=chat.scrollHeight}
function quickAsk(text){document.getElementById('chatInput').value=text;document.getElementById('chatForm').requestSubmit()}
async function sendMessage(event,agentId){event.preventDefault();const input=document.getElementById('chatInput');const form=document.getElementById('chatForm');const text=input.value.trim();if(!text)return;input.value='';if(form)form.querySelector('button').disabled=true;addMsg('user',text);chatMessages.push({role:'user',content:text});addMsg('bot','Escribiendo...');const pending=document.querySelector('#chat .msg.bot:last-child');try{const res=await fetch('/api/agent-chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:agentId,conversation_id:conversationId,messages:chatMessages})});const data=await res.json();conversationId=data.conversation_id;pending.textContent=data.reply||'No pude responder ahora. Revisa la configuración e intenta de nuevo.';chatMessages.push({role:'assistant',content:pending.textContent});if(data.lead_created)toast('Oportunidad detectada')}catch(e){pending.textContent='No pude conectar con el vendedor IA en este momento. Intenta nuevamente en unos segundos.'}finally{if(form)form.querySelector('button').disabled=false;input.focus()}}
"""


def main():
    init_db()
    port = int(os.environ.get("PORT", "8765"))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), App)
    print(f"{APP_NAME} listo en http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()



