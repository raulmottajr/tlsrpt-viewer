import os
import json
import gzip
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

        filename
