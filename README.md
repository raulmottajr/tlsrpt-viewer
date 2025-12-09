# TLSRPT Viewer (Upload + IMAP)

Pequena aplicação Flask para visualizar relatórios TLS-RPT (RFC 8460):

- Upload de arquivos `.json` ou `.json.gz`
- Leitura automática de relatórios via IMAP (caixa onde chegam os TLS reports)

## Uso local (opcional, se tiver Python)

- Criar venv
- `pip install -r requirements.txt`
- `python app.py`
- Acessar http://localhost:5000

## Deploy no Render

O arquivo `render.yaml` define:

- Tipo: web
- Runtime: Python
- Build: `pip install -r requirements.txt`
- Start: `gunicorn -b 0.0.0.0:$PORT app:app`

Basta conectar o repositório no Render e criar um Web Service.

## Segurança

- A aplicação não armazena credenciais IMAP.
- As credenciais são usadas apenas na requisição.
- Em produção, recomenda-se proteger o acesso (VPN, IP allowlist, autenticação, etc.).
