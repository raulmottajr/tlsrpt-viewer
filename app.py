import os
import json
import gzip
import sqlite3
import imaplib
import email
from email.header import decode_header
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)

from authlib.integrations.flask_client import OAuth

app = Flask(__name__)

# Secret key para assinar sessão
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")

# Cada versão nova do schema você pode trocar o nome do arquivo
DB_PATH = os.environ.get("TLSRPT_DB_PATH", "tlsrpt_v2.db")

# --------- OAuth com Google ---------
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    api_base_url="https://openidconnect.googleapis.com/v1/",
    client_kwargs={
        "scope": "openid email profile",
    },
)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


def get_current_user_id():
    user = session.get("user")
    if not user:
        return None
    # usa o "sub" (ID estável do Google). Se quiser, pode usar email.
    return user.get("sub") or user.get("email")


# --------- Banco de dados ---------


def init_db():
    """Cria a tabela de relatórios se ainda não existir."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            source TEXT,
            organization_name TEXT,
            contact_info TEXT,
            report_id TEXT,
            policy_type TEXT,
            policy_domain TEXT,
            mx_host TEXT,
            start_datetime TEXT,
            end_datetime TEXT,
            total_success INTEGER,
            total_failure INTEGER
        )
        """
    )
    conn.commit()
    conn.close()


def store_report(parsed, source="upload"):
    """
    Guarda no SQLite um resumo de cada policy do relatório,
    vinculado ao usuário logado.
    """
    user_id = get_current_user_id()
    if not user_id or not parsed:
        return

    date_range = parsed.get("date_range") or {}
    start = date_range.get("start")
    end = date_range.get("end")
    org = parsed.get("organization_name")
    contact = parsed.get("contact_info")
    rid = parsed.get("report_id")

    policies = parsed.get("policies") or []
    if not policies:
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for p in policies:
        cur.execute(
            """
            INSERT INTO reports (
                user_id,
                source,
                organization_name,
                contact_info,
                report_id,
                policy_type,
                policy_domain,
                mx_host,
                start_datetime,
                end_datetime,
                total_success,
                total_failure
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                source,
                org,
                contact,
                rid,
                p.get("policy_type"),
                p.get("policy_domain"),
                p.get("mx_host"),
                start,
                end,
                p.get("total_success"),
                p.get("total_failure"),
            ),
        )

    conn.commit()
    conn.close()


# --------- Parse TLS-RPT ---------


def parse_tlsrpt_json(data):
    """
    Extrai as principais informações de um relatório TLS-RPT (RFC 8460).
    """
    result = {
        "organization_name": data.get("organization-name"),
        "contact_info": data.get("contact-info"),
        "report_id": data.get("report-id"),
        "date_range": None,
        "policies": [],
        "raw": data,
    }

    date_range = data.get("date-range") or {}
    if date_range:
        result["date_range"] = {
            "start": date_range.get("start-datetime"),
            "end": date_range.get("end-datetime"),
        }

    policies = data.get("policies") or data.get("tls-report") or []
    for p in policies:
        policy = p.get("policy", {})
        summary = p.get("summary", {})
        failures = p.get("failure-details", [])

        result["policies"].append(
            {
                "policy_type": policy.get("policy-type"),
                "policy_string": policy.get("policy-string"),
                "policy_domain": policy.get("policy-domain"),
                "mx_host": policy.get("mx-host"),
                "total_success": summary.get("total-successful-session-count"),
                "total_failure": summary.get("total-failure-session-count"),
                "failures": failures,
            }
        )

    return result


def load_report_bytes(file_storage):
    """
    Lê o arquivo enviado. Se for .gz, descompacta.
    Retorna bytes com o JSON.
    """
    content = file_storage.read()
    filename = (file_storage.filename or "").lower()

    if filename.endswith(".gz"):
        content = gzip.decompress(content)

    return content


# --------- Rotas de autenticação ---------


@app.route("/login")
def login():
    redirect_uri = url_for("auth_callback", _external=True, _scheme="https")
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    token = google.authorize_access_token()
    resp = google.get("userinfo", token=token)
    userinfo = resp.json()

    # Guarda o básico na sessão
    session["user"] = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
        "picture": userinfo.get("picture"),
    }
    flash("Login efetuado com sucesso.", "success")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Sessão encerrada.", "success")
    return redirect(url_for("index"))


# --------- Rotas principais ---------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    # multi-upload: vár
