import os
import json
import gzip
import io
import imaplib
import email
from email.header import decode_header

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

app = Flask(__name__)

# Use uma secret key simples para testes. Em produção, coloque via variável de ambiente.
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")


def parse_tlsrpt_json(data):
    """
    Tenta extrair as principais informações de um relatório TLS-RPT
    conforme RFC 8460. Se o formato for diferente, ainda assim
    devolve o JSON bruto para visualização.
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

    # RFC fala em "policies", mas alguns provedores podem variar
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "report_file" not in request.files:
        flash("Nenhum arquivo enviado.", "error")
        return redirect(url_for("index"))

    file = request.files["report_file"]
    if file.filename == "":
        flash("Selecione um arquivo para enviar.", "error")
        return redirect(url_for("index"))

    try:
        raw_bytes = load_report_bytes(file)
        text = raw_bytes.decode("utf-8")
        data = json.loads(text)
        parsed = parse_tlsrpt_json(data)
    except Exception as e:
        flash(f"Erro ao processar o arquivo: {e}", "error")
        return redirect(url_for("index"))

    return render_template("upload_results.html", report=parsed)


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


@app.route("/imap", methods=["POST"])
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

        # Busca todas as mensagens; pega as mais recentes primeiro
        status, data = imap.search(None, "ALL")
        if status != "OK":
            raise RuntimeError("Falha ao buscar mensagens.")

        ids = data[0].split()
        ids = ids[-limit:]  # últimas N mensagens

        for msg_id in reversed(ids):
            status, msg_data = imap.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            # Metadados básicos do e-mail
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


if __name__ == "__main__":
    # Para rodar localmente: python app.py
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
