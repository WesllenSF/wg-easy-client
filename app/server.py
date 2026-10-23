#!/usr/bin/env python3
"""wg-easy-client: servidor HTTP com a API JSON e a página web."""
import base64
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import core

VERSION = "1.0.0"
DATA_DIR = os.environ.get("WGEC_DATA", "/config")
HOST = os.environ.get("WGEC_HOST", "0.0.0.0")
PORT = int(os.environ.get("WGEC_PORT", "51821"))
ENV_PASSWORD = os.environ.get("WGEC_PASSWORD", "")
MOCK = os.environ.get("WGEC_MOCK") == "1"
ALLOW_SCRIPTS = os.environ.get("WGEC_ALLOW_SCRIPTS") == "1"
SESSION_SECONDS = 7 * 86400
MAX_BODY = 8 * 1024 * 1024
COOKIE = "wgec_session"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

mgr = None
auth = None


# ---------------------------------------------------------------- senha e sessão

def hash_password(pw, iterations=120_000):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def verify_password(pw, stored):
    try:
        _, it, salt, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc, base64.b64decode(h))


class Auth:
    def __init__(self, manager):
        self.mgr = manager
        with manager.lock:
            if "secret" not in manager.settings:
                manager.settings["secret"] = secrets.token_hex(32)
                manager.save_settings()
        self.env_hash = hash_password(ENV_PASSWORD) if ENV_PASSWORD else None

    def stored(self):
        return self.env_hash or self.mgr.settings.get("password")

    def needs_setup(self):
        return not self.stored()

    def verify(self, pw):
        st = self.stored()
        return bool(st) and isinstance(pw, str) and verify_password(pw, st)

    def set_password(self, pw):
        with self.mgr.lock:
            self.mgr.settings["password"] = hash_password(pw)
            self.mgr.save_settings()

    def _sig(self, exp):
        # inclui o hash da senha: trocar a senha encerra as sessões antigas
        msg = f"{exp}.{self.stored()}".encode()
        return hmac.new(self.mgr.settings["secret"].encode(), msg, "sha256").hexdigest()

    def token(self):
        exp = int(time.time()) + SESSION_SECONDS
        return f"{exp}.{self._sig(exp)}"

    def check(self, tok):
        if not tok or not self.stored():
            return False
        exp, _, sig = tok.partition(".")
        if not exp.isdigit() or int(exp) < time.time():
            return False
        return hmac.compare_digest(sig, self._sig(exp))


# ---------------------------------------------------------------- arquivos estáticos

STATIC = {}
for _fn, _ctype in (("index.html", "text/html; charset=utf-8"),
                    ("manifest.webmanifest", "application/manifest+json"),
                    ("icon.svg", "image/svg+xml")):
    with open(os.path.join(STATIC_DIR, _fn), "rb") as _fh:
        _data = _fh.read()
    STATIC["/" + _fn] = (_ctype, _data, gzip.compress(_data, 9))
STATIC["/"] = STATIC["/index.html"]

# a página não carrega nada de fora: só o próprio servidor
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; manifest-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


# ---------------------------------------------------------------- HTTP

class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


class Handler(BaseHTTPRequestHandler):
    server_version = "wg-easy-client"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def send(self, status, body=b"", ctype="application/json", headers=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json(self, obj, status=200, headers=()):
        self.send(status, json.dumps(obj).encode(), headers=headers)

    def body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "Content-Length inválido")
        if n < 0:
            raise ApiError(400, "Content-Length inválido")
        if n > MAX_BODY:
            raise ApiError(413, "requisição grande demais")
        if not n:
            return {}
        try:
            data = json.loads(self.rfile.read(n))
        except ValueError:
            raise ApiError(400, "JSON inválido")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON inválido")
        return data

    def cookie(self):
        c = SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except Exception:
            return None
        return c[COOKIE].value if COOKIE in c else None

    def session_cookie(self, tok, max_age=SESSION_SECONDS):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return ("Set-Cookie", f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}")

    def static(self, path):
        ctype, raw, gz = STATIC[path]
        headers = [("Content-Security-Policy", CSP)]
        if "gzip" in self.headers.get("Accept-Encoding", ""):
            self.send(200, gz, ctype, headers + [("Content-Encoding", "gzip"), ("Vary", "Accept-Encoding")])
        else:
            self.send(200, raw, ctype, headers)

    def do_GET(self):
        self.route("GET")

    def do_HEAD(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        path = urlsplit(self.path).path
        try:
            if method == "GET" and path in STATIC:
                return self.static(path)
            if not path.startswith("/api/"):
                raise ApiError(404, "não encontrado")
            # cabeçalho próprio obriga o navegador a fazer preflight: bloqueia CSRF
            if method != "GET" and self.headers.get("X-WGEC") != "1":
                raise ApiError(403, "requisição recusada")
            for m, rx, fn, public in ROUTES:
                mt = rx.fullmatch(path)
                if m == method and mt:
                    if not public and not auth.check(self.cookie()):
                        raise ApiError(401, "não autenticado")
                    return fn(self, *[unquote(g) for g in mt.groups()])
            raise ApiError(404, "não encontrado")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except ApiError as e:
            self.json({"error": str(e)}, e.status)
        except core.ConfigError as e:
            self.json({"error": str(e)}, 400)
        except core.NotFound as e:
            self.json({"error": str(e)}, 404)
        except core.WgError as e:
            core.log(f"erro: {e}")
            self.json({"error": str(e)}, 500)
        except Exception as e:
            core.log(f"erro interno: {e!r}")
            self.json({"error": "erro interno"}, 500)


# ---------------------------------------------------------------- rotas

def _password_arg(b, key="password"):
    pw = b.get(key)
    if not isinstance(pw, str) or len(pw) < 8:
        raise ApiError(400, "a senha precisa ter pelo menos 8 caracteres")
    return pw


def api_session(h):
    h.json({"authenticated": auth.check(h.cookie()), "needsSetup": auth.needs_setup(),
            "passwordFromEnv": bool(ENV_PASSWORD), "mock": MOCK, "version": VERSION})


def api_setup(h):
    pw = _password_arg(h.body())
    with mgr.lock:
        if not auth.needs_setup():
            raise ApiError(409, "a senha já foi definida")
        auth.set_password(pw)
    core.log("senha de acesso definida")
    h.json({"ok": True}, headers=[h.session_cookie(auth.token())])


def api_login(h):
    if not auth.verify(h.body().get("password")):
        time.sleep(1)
        core.log(f"falha de login de {h.client_address[0]}")
        raise ApiError(401, "senha incorreta")
    h.json({"ok": True}, headers=[h.session_cookie(auth.token())])


def api_logout(h):
    h.json({"ok": True}, headers=[h.session_cookie("", 0)])


def api_password(h):
    if ENV_PASSWORD:
        raise ApiError(409, "a senha é definida pela variável WGEC_PASSWORD")
    b = h.body()
    if not auth.verify(b.get("current")):
        time.sleep(1)
        raise ApiError(400, "senha atual incorreta")
    auth.set_password(_password_arg(b, "new"))
    core.log("senha de acesso alterada")
    h.json({"ok": True}, headers=[h.session_cookie(auth.token())])


def api_list(h):
    h.json({"tunnels": mgr.list()})


def api_get(h, name):
    h.json(mgr.detail(name))


def api_create(h):
    b = h.body()
    name = b.get("name", "")
    mgr.create(name, b.get("config"), bool(b.get("killswitch")))
    h.json(mgr.detail(name), 201)


def api_update(h, name):
    b = h.body()
    new = b.get("name") or name
    mgr.update(name, new, b.get("config"), bool(b.get("killswitch")))
    h.json(mgr.detail(new))


def api_delete(h, name):
    mgr.delete(name)
    h.json({"ok": True})


def api_activate(h, name):
    mgr.activate(name)
    h.json(mgr.detail(name))


def api_deactivate(h, name):
    mgr.deactivate(name)
    h.json(mgr.detail(name))


def api_import(h):
    files = []
    for f in h.body().get("files", []):
        try:
            files.append((str(f["name"]), base64.b64decode(f["data"])))
        except (KeyError, TypeError, ValueError):
            raise ApiError(400, "arquivo inválido")
    h.json(mgr.import_files(files))


def api_export(h):
    fname = time.strftime("wg-easy-client-%Y%m%d.zip")
    h.send(200, mgr.export_zip(), "application/zip",
           [("Content-Disposition", f'attachment; filename="{fname}"')])


def api_genkey(h):
    k = core.genkey()
    h.json({"privateKey": k, "publicKey": core.pubkey(k)})


def api_pubkey(h):
    try:
        h.json({"publicKey": core.pubkey(str(h.body().get("privateKey", "")))})
    except core.ConfigError:
        h.json({"publicKey": None})


def api_log(h):
    with core._log_lock:
        lines = [{"t": t, "m": m} for t, m in core.LOG]
    h.json({"lines": lines})


NAME = r"([^/]+)"
ROUTES = [(m, re.compile(p), fn, public) for m, p, fn, public in (
    ("GET", r"/api/session", api_session, True),
    ("POST", r"/api/setup", api_setup, True),
    ("POST", r"/api/login", api_login, True),
    ("POST", r"/api/logout", api_logout, True),
    ("POST", r"/api/password", api_password, False),
    ("GET", r"/api/tunnels", api_list, False),
    ("POST", r"/api/tunnels", api_create, False),
    ("GET", rf"/api/tunnels/{NAME}", api_get, False),
    ("PUT", rf"/api/tunnels/{NAME}", api_update, False),
    ("DELETE", rf"/api/tunnels/{NAME}", api_delete, False),
    ("POST", rf"/api/tunnels/{NAME}/activate", api_activate, False),
    ("POST", rf"/api/tunnels/{NAME}/deactivate", api_deactivate, False),
    ("POST", r"/api/import", api_import, False),
    ("GET", r"/api/export", api_export, False),
    ("GET", r"/api/genkey", api_genkey, False),
    ("POST", r"/api/pubkey", api_pubkey, False),
    ("GET", r"/api/log", api_log, False),
)]


# ---------------------------------------------------------------- main

def main():
    global mgr, auth
    backend = core.MockBackend() if MOCK else core.RealBackend()
    mgr = core.Manager(DATA_DIR, backend, ALLOW_SCRIPTS)
    auth = Auth(mgr)
    core.log(f"wg-easy-client {VERSION}" + (" (modo simulado)" if MOCK else ""))
    if auth.needs_setup():
        core.log("nenhuma senha definida: crie uma no primeiro acesso à página")
    mgr.startup()

    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True

    def stop(*_):
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    core.log(f"página web em http://{HOST}:{PORT}")
    srv.serve_forever()
    core.log("encerrando: desativando túneis")
    mgr.shutdown()


if __name__ == "__main__":
    main()
