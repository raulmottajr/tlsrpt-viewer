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

from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key para sessão (em produção, coloque via variável de ambiente)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")

# Arquivo de banco de dados (pode ser sobrescrito por variável de ambiente)
DB_PATH = os.environ.get("TLSRPT_DB_PATH", "tlsrpt_v2.db")


# ------------------ Banco de dados ------------------


def init_db():
    """Cria as tabelas de usuários e relatórios se ainda não existirem."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Usuários
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Relatórios TLS-RPT vinculados ao usuário
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
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
            total_failure INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


def get_current_user():
    """Retorna (user_id, email) a partir da sessão, ou (None, None)."""
    user_id = session.get("user_id")
    email = session.get("user_email")
    return user_id, email


def store_report(parsed, source="upload"):
    """
    Guarda no SQLite um resumo de cada policy do relatório,
    vinculado ao usuário logado.
    """
    user_id, _ = get_current_user()
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


# ------------------ Utilidades TLS-RPT ------------------


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


def decode_maybe(value):
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return value.decode(errors="replace")
    return value


def parse_imap_message(msg):
    """
    Procura anexos TLS-RPT (json ou json.gz) dentro de uma mensagem.
    Pode retornar vários relatórios por e-mail.
    """
    reports = []

    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", "")
        if "attachment" not in content_disposition.lower():
            continue

        filename = part.get_filename()
        if not filename:
            continue

        filename_decoded, encoding = decode_header(filename)[0]
        filename_decoded = decode_maybe(filename_decoded).lower()

        if not (
            filename_decoded.endswith(".json")
            or filename_decoded.endswith(".json.gz")
            or filename_decoded.endswith(".gz")
        ):
            continue

        payload = part.get_payload(decode=True)
        if not payload:
            continue

        try:
            if filename_decoded.endswith(".gz"):
                payload = gzip.decompress(payload)
            text = payload.decode("utf-8")
            data = json.loads(text)
            reports.append(parse_tlsrpt_json(data))
        except Exception:
            continue

    return reports


# ------------------ Autenticação simples ------------------


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user_id, _ = get_current_user()
        if not user_id:
            flash("Faça login para usar esta funcionalidade.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not email or not password:
            flash("E-mail e senha são obrigatórios.", "error")
            return redirect(url_for("register"))

        if password != password2:
            flash("As senhas não coincidem.", "error")
            return redirect(url_for("register"))

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cur.fetchone()
        if existing:
            conn.close()
            flash("Já existe um usuário com este e-mail.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash),
        )
        conn.commit()
        conn.close()

        flash("Usuário criado com sucesso. Faça login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,),
        )
        row = cur.fetchone()
        conn.close()

        if not row:
            flash("Usuário ou senha inválidos.", "error")
            return redirect(url_for("login"))

        user_id, password_hash = row
        if not check_password_hash(password_hash, password):
            flash("Usuário ou senha inválidos.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user_id
        session["user_email"] = email
        flash("Login efetuado com sucesso.", "success")
        # Depois de logar, cai sempre no dashboard (/stats)
        return redirect(url_for("stats"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Sessão encerrada.", "success")
    return redirect(url_for("index"))


# ------------------ Rotas principais ------------------


@app.route("/")
def index():
    user_id, email = get_current_user()
    return render_template("index.html", user_email=email)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    # multi-upload: vários arquivos
    files = request.files.getlist("report_files")
    if not files or files[0].filename == "":
        flash("Selecione pelo menos um arquivo para enviar.", "error")
        return redirect(url_for("index"))

    parsed_reports = []

    for file in files:
        if not file.filename:
            continue

        try:
            raw_bytes = load_report_bytes(file)
            text = raw_bytes.decode("utf-8")
            data = json.loads(text)
            parsed = parse_tlsrpt_json(data)
            parsed["filename"] = file.filename
            parsed_reports.append(parsed)

            store_report(parsed, source="upload")
        except Exception as e:
            flash(f"Erro ao processar o arquivo {file.filename}: {e}", "error")

    if not parsed_reports:
        return redirect(url_for("index"))

    return render_template("upload_results.html", reports=parsed_reports)


@app.route("/imap", methods=["POST"])
@login_required
def imap_view():
    host = request.form.get("host", "").strip()
    port = request.form.get("port", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    mailbox = request.form.get("mailbox", "INBOX").strip() or "INBOX"
    limit = request.form.get("limit", "").strip()

    if not host or not username or not password:
        flash("Host, usuário e senha são obrigatórios.", "error")
        return redirect(url_for("index"))

    try:
        port = int(port) if port else 993
        limit = int(limit) if limit else 20
    except ValueError:
        flash("Porta e limite devem ser números inteiros.", "error")
        return redirect(url_for("index"))

    all_reports = []
    errors = []

    try:
        imap = imaplib.IMAP4_SSL(host, port)
        imap.login(username, password)
        imap.select(mailbox)

        status, data = imap.search(None, "ALL")
        if status != "OK":
            raise RuntimeError("Falha ao buscar mensagens.")

        ids = data[0].split()
        ids = ids[-limit:]

        for msg_id in reversed(ids):
            status, msg_data = imap.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject, encoding = decode_header(msg.get("Subject", ""))[0]
            subject = decode_maybe(subject)
            from_ = decode_maybe(msg.get("From", ""))
            date_ = decode_maybe(msg.get("Date", ""))

            reports = parse_imap_message(msg)
            for r in reports:
                r["email_subject"] = subject
                r["email_from"] = from_
                r["email_date"] = date_
                all_reports.append(r)

                store_report(r, source="imap")

        imap.close()
        imap.logout()

    except Exception as e:
        errors.append(str(e))

    return render_template(
        "imap_results.html",
        reports=all_reports,
        errors=errors,
        host=host,
        username=username,
        mailbox=mailbox,
        limit=limit,
    )


@app.route("/stats")
@login_required
def stats():
    """
    Estatísticas por usuário: soma sucessos e falhas por data de início
    apenas do usuário logado.
    """
    user_id, _ = get_current_user()
    if not user_id:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            start_datetime,
            SUM(COALESCE(total_success, 0)) AS success,
            SUM(COALESCE(total_failure, 0)) AS failure
        FROM reports
        WHERE start_datetime IS NOT NULL
          AND user_id = ?
        GROUP BY start_datetime
        ORDER BY start_datetime
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()

    labels = [r[0] for r in rows]
    success = [r[1] for r in rows]
    failure = [r[2] for r in rows]

    return render_template("stats.html", labels=labels, success=success, failure=failure)


# Cria o banco na partida
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
