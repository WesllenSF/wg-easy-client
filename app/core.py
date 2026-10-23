"""Núcleo do wg-easy-client: chaves, configuração e controle dos túneis WireGuard."""
import base64
import io
import json
import os
import re
import secrets
import subprocess
import threading
import time
import zipfile
from collections import deque


# ---------------------------------------------------------------- log

LOG = deque(maxlen=1000)
_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        LOG.append((time.time(), msg))
    print(time.strftime("%Y-%m-%d %H:%M:%S ") + msg, flush=True)


# ---------------------------------------------------------------- erros

class ConfigError(ValueError):
    pass


class NotFound(LookupError):
    pass


class WgError(RuntimeError):
    pass


# ---------------------------------------------------------------- chaves (X25519, RFC 7748)

_P = 2 ** 255 - 19
_A24 = 121665


def _clamp(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def x25519(k, u):
    k = int.from_bytes(_clamp(k), "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def decode_key(s):
    try:
        b = base64.b64decode(s.strip(), validate=True)
    except ValueError:
        raise ConfigError("chave inválida (base64)")
    if len(b) != 32:
        raise ConfigError("chave inválida (precisa ter 32 bytes)")
    return b


def genkey():
    return base64.b64encode(_clamp(secrets.token_bytes(32))).decode()


def pubkey(private_b64):
    return base64.b64encode(x25519(decode_key(private_b64), (9).to_bytes(32, "little"))).decode()


# ---------------------------------------------------------------- configuração

# mesmo formato aceito pelo kernel para nome de interface ("." e ".." não)
NAME_RE = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9_=+.-]{1,15}$")
IFACE_KEYS = {"privatekey", "listenport", "fwmark", "address", "dns", "mtu", "table",
              "preup", "postup", "predown", "postdown", "saveconfig"}
PEER_KEYS = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
SCRIPT_KEYS = {"preup", "postup", "predown", "postdown"}
INT_KEYS = {"listenport", "mtu", "persistentkeepalive"}


def _split(values):
    return [x.strip() for v in values for x in v.split(",") if x.strip()]


def _first(section, key):
    v = section.get(key)
    return v[-1] if v else None


def check_name(name):
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ConfigError("nome inválido: use até 15 caracteres entre A-Z a-z 0-9 _ = + . -")


def parse_config(text):
    """Valida um .conf do wg-quick e devolve um resumo dos campos."""
    if not isinstance(text, str):
        raise ConfigError("configuração ausente")
    sections, cur = [], None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            kind = line[1:-1].strip().lower()
            if kind not in ("interface", "peer"):
                raise ConfigError(f"linha {n}: seção desconhecida {line}")
            cur = {"_kind": kind}
            sections.append(cur)
            continue
        if cur is None:
            raise ConfigError(f"linha {n}: chave fora de uma seção")
        if "=" not in line:
            raise ConfigError(f"linha {n}: esperado 'Chave = valor'")
        k, v = line.split("=", 1)
        k, v = k.strip().lower(), v.strip()
        allowed = IFACE_KEYS if cur["_kind"] == "interface" else PEER_KEYS
        if k not in allowed:
            raise ConfigError(f"linha {n}: chave desconhecida '{k}' em [{cur['_kind'].title()}]")
        if k in INT_KEYS and not v.isdigit() and v.lower() != "off":
            raise ConfigError(f"linha {n}: '{k}' precisa ser um número")
        cur.setdefault(k, []).append(v)

    ifaces = [s for s in sections if s["_kind"] == "interface"]
    if len(ifaces) != 1:
        raise ConfigError("a configuração precisa de exatamente uma seção [Interface]")
    iface = ifaces[0]
    if "privatekey" not in iface:
        raise ConfigError("[Interface] sem PrivateKey")
    try:
        pub = pubkey(_first(iface, "privatekey"))
    except ConfigError as e:
        raise ConfigError(f"PrivateKey: {e}")

    peers = []
    for p in (s for s in sections if s["_kind"] == "peer"):
        if "publickey" not in p:
            raise ConfigError("[Peer] sem PublicKey")
        for key in ("publickey", "presharedkey"):
            if key in p:
                try:
                    decode_key(_first(p, key))
                except ConfigError as e:
                    raise ConfigError(f"{'PublicKey' if key == 'publickey' else 'PresharedKey'}: {e}")
        peers.append({
            "publicKey": _first(p, "publickey"),
            "presharedKey": "presharedkey" in p,
            "allowedIps": _split(p.get("allowedips", [])),
            "endpoint": _first(p, "endpoint"),
            "keepalive": _first(p, "persistentkeepalive"),
        })

    return {
        "publicKey": pub,
        "listenPort": _first(iface, "listenport"),
        "addresses": _split(iface.get("address", [])),
        "dns": _split(iface.get("dns", [])),
        "mtu": _first(iface, "mtu"),
        "hasScripts": any(k in iface for k in SCRIPT_KEYS),
        "fullTunnel": any(ip in ("0.0.0.0/0", "::/0") for p in peers for ip in p["allowedIps"]),
        "peers": peers,
    }


# ---------------------------------------------------------------- backends

KS_CHAIN = "WGEC_KILLSWITCH"


def _split_endpoint(ep):
    host, _, port = ep.rpartition(":")
    return host.strip("[]"), port


class RealBackend:
    """Controla o WireGuard de verdade via wg, wg-quick e iptables."""

    def __init__(self):
        legacy = os.environ.get("WGEC_IPTABLES") == "legacy"
        self.ipt = ("iptables-legacy", "ip6tables-legacy") if legacy else ("iptables", "ip6tables")

    def _run(self, *cmd, check=True, log_output=False):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            raise WgError(f"comando não encontrado: {cmd[0]}")
        except subprocess.TimeoutExpired:
            raise WgError(f"tempo esgotado executando {cmd[0]}")
        if log_output:
            for line in p.stderr.splitlines():
                log(line)
        if check and p.returncode:
            raise WgError((p.stderr or p.stdout).strip() or f"{cmd[0]} falhou ({p.returncode})")
        return p.stdout

    def up(self, path):
        self._run("wg-quick", "up", path, log_output=True)

    def down(self, path):
        self._run("wg-quick", "down", path, log_output=True)

    def interfaces(self):
        return set(self._run("wg", "show", "interfaces").split())

    def dump(self, iface):
        # A primeira linha do dump contém a chave privada: nunca registrar no log.
        lines = self._run("wg", "show", iface, "dump").strip().splitlines()
        if not lines:
            return None
        f = lines[0].split("\t")
        res = {"listenPort": f[2], "fwmark": f[3], "peers": []}
        for line in lines[1:]:
            p = line.split("\t")
            res["peers"].append({
                "publicKey": p[0],
                "endpoint": None if p[2] == "(none)" else p[2],
                "allowedIps": [] if p[3] == "(none)" else p[3].split(","),
                "handshake": int(p[4]),
                "rx": int(p[5]),
                "tx": int(p[6]),
                "keepalive": None if p[7] == "off" else p[7],
            })
        return res

    def killswitch_on(self, iface, fwmark, endpoints):
        for ipt, v6 in ((self.ipt[0], False), (self.ipt[1], True)):
            try:
                self._ks_clear(ipt)
                self._run(ipt, "-N", KS_CHAIN)
                rules = [
                    ["-o", "lo"],
                    ["-o", iface],
                    # respostas a conexões que chegaram de fora (ex.: esta página, SSH)
                    ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "REPLY"],
                    ["-m", "addrtype", "--dst-type", "LOCAL"],
                ]
                if fwmark and fwmark != "off":
                    rules.append(["-m", "mark", "--mark", fwmark])
                for host, port in endpoints:
                    if (":" in host) == v6:
                        rules.append(["-d", host, "-p", "udp", "--dport", port])
                for r in rules:
                    self._run(ipt, "-A", KS_CHAIN, *r, "-j", "RETURN")
                self._run(ipt, "-A", KS_CHAIN, "-j", "REJECT")
                self._run(ipt, "-I", "OUTPUT", "-j", KS_CHAIN)
            except WgError as e:
                if not v6:
                    self._ks_clear(ipt)
                    raise WgError(f"falha ao aplicar o kill-switch: {e}")
                log(f"aviso: kill-switch IPv6 não aplicado: {e}")
        log(f"kill-switch ativado para {iface}")

    def _ks_clear(self, ipt):
        for _ in range(10):
            try:
                self._run(ipt, "-D", "OUTPUT", "-j", KS_CHAIN)
            except WgError:
                break
        self._run(ipt, "-F", KS_CHAIN, check=False)
        self._run(ipt, "-X", KS_CHAIN, check=False)

    def killswitch_off(self):
        for ipt in self.ipt:
            try:
                self._ks_clear(ipt)
            except WgError:
                pass

    def restore_dns(self):
        self._run("resolvconf", "-d", "wgec", "-f", check=False)


class MockBackend:
    """Simula o WireGuard para testar a interface sem root (WGEC_MOCK=1)."""

    def __init__(self):
        self.up_ifaces = {}

    @staticmethod
    def _name(path):
        return os.path.basename(path)[:-5]

    def up(self, path):
        name = self._name(path)
        if name in self.up_ifaces:
            raise WgError(f"wg-quick: `{name}' already exists")
        with open(path, encoding="utf-8") as fh:
            info = parse_config(fh.read())
        self.up_ifaces[name] = (time.time(), info)
        log(f"[#] ip link add {name} type wireguard (simulado)")
        for a in info["addresses"]:
            log(f"[#] ip address add {a} dev {name} (simulado)")
        log(f"[#] ip link set up dev {name} (simulado)")

    def down(self, path):
        name = self._name(path)
        if self.up_ifaces.pop(name, None) is None:
            raise WgError(f"wg-quick: `{name}' is not a WireGuard interface")
        log(f"[#] ip link delete dev {name} (simulado)")

    def interfaces(self):
        return set(self.up_ifaces)

    def dump(self, iface):
        start, info = self.up_ifaces[iface]
        el = time.time() - start
        return {
            "listenPort": info["listenPort"] or "51820",
            "fwmark": "0xca6c" if info["fullTunnel"] else "off",
            "peers": [{
                "publicKey": p["publicKey"],
                "endpoint": p["endpoint"],
                "allowedIps": p["allowedIps"],
                "handshake": int(time.time() - (el % 120)) if p["endpoint"] else 0,
                "rx": int(el * 31500),
                "tx": int(el * 8200),
                "keepalive": p["keepalive"],
            } for p in info["peers"]],
        }

    def killswitch_on(self, iface, fwmark, endpoints):
        log(f"kill-switch ativado para {iface} (simulado)")

    def killswitch_off(self):
        pass

    def restore_dns(self):
        pass


# ---------------------------------------------------------------- gerenciador

def _sanitize(stem):
    name = re.sub(r"[^A-Za-z0-9_=+.-]", "_", stem)[:15]
    return name if NAME_RE.match(name) else "tunel"


class Manager:
    MAX_IMPORT_FILE = 256 * 1024

    def __init__(self, data_dir, backend, allow_scripts=False):
        self.backend = backend
        self.allow_scripts = allow_scripts
        self.tdir = os.path.join(data_dir, "tunnels")
        self.settings_path = os.path.join(data_dir, "settings.json")
        os.makedirs(self.tdir, mode=0o700, exist_ok=True)
        self.lock = threading.RLock()
        try:
            with open(self.settings_path, encoding="utf-8") as fh:
                self.settings = json.load(fh)
        except FileNotFoundError:
            self.settings = {}
        self.settings.setdefault("killswitch", {})

    # -- arquivos

    def save_settings(self):
        tmp = self.settings_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.settings, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.settings_path)

    def path(self, name):
        return os.path.join(self.tdir, name + ".conf")

    def names(self):
        names = [f[:-5] for f in os.listdir(self.tdir) if f.endswith(".conf") and NAME_RE.match(f[:-5])]
        return sorted(names, key=str.lower)

    def exists(self, name):
        return bool(NAME_RE.match(name)) and os.path.isfile(self.path(name))

    def read(self, name):
        if not self.exists(name):
            raise NotFound(f"túnel '{name}' não encontrado")
        with open(self.path(name), encoding="utf-8") as fh:
            return fh.read()

    def _write(self, name, text):
        text = text.replace("\r\n", "\n")
        if not text.endswith("\n"):
            text += "\n"
        tmp = self.path(name) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path(name))

    def validate(self, text):
        info = parse_config(text)
        if info["hasScripts"] and not self.allow_scripts:
            raise ConfigError("PreUp/PostUp/PreDown/PostDown estão bloqueados "
                              "(defina WGEC_ALLOW_SCRIPTS=1 para permitir)")
        return info

    def _unique(self, name):
        cand, i = name, 2
        while self.exists(cand):
            suf = f"-{i}"
            cand = name[:15 - len(suf)] + suf
            i += 1
        return cand

    # -- consulta

    def _up_set(self):
        try:
            return self.backend.interfaces()
        except WgError as e:
            log(f"erro ao consultar interfaces: {e}")
            return set()

    def active(self):
        up = self._up_set()
        return [n for n in self.names() if n in up]

    def list(self):
        up = self._up_set()
        return [{"name": n, "active": n in up} for n in self.names()]

    def detail(self, name):
        text = self.read(name)
        res = {"name": name, "config": text, "active": False,
               "killswitch": bool(self.settings["killswitch"].get(name))}
        try:
            info = parse_config(text)
        except ConfigError as e:
            res["error"] = str(e)
            return res
        res["active"] = name in self._up_set()
        live = None
        if res["active"]:
            try:
                live = self.backend.dump(name)
            except WgError as e:
                res["error"] = str(e)
        now = int(time.time())
        live_peers = {p["publicKey"]: p for p in (live or {}).get("peers", [])}
        peers = []
        for p in info["peers"]:
            lp = live_peers.get(p["publicKey"])
            peer = dict(p, handshakeAgo=None, rx=None, tx=None)
            if lp:
                peer["endpoint"] = lp["endpoint"] or p["endpoint"]
                peer["handshakeAgo"] = now - lp["handshake"] if lp["handshake"] else None
                peer["rx"], peer["tx"] = lp["rx"], lp["tx"]
            peers.append(peer)
        res["interface"] = {
            "publicKey": info["publicKey"],
            "listenPort": live["listenPort"] if live else info["listenPort"],
            "addresses": info["addresses"],
            "dns": info["dns"],
            "mtu": info["mtu"],
            "fullTunnel": info["fullTunnel"],
        }
        res["peers"] = peers
        return res

    # -- ativação

    def _up(self, name):
        self.backend.up(self.path(name))
        log(f"túnel {name} ativado")
        if not self.settings["killswitch"].get(name):
            return
        try:
            d = self.backend.dump(name) or {"fwmark": "off", "peers": []}
            eps = [_split_endpoint(p["endpoint"]) for p in d["peers"] if p["endpoint"]]
            self.backend.killswitch_on(name, d["fwmark"], eps)
        except WgError:
            # sem kill-switch o túnel não sobe: falha segura
            self.backend.down(self.path(name))
            raise

    def _down(self, name):
        self.backend.killswitch_off()
        self.backend.down(self.path(name))
        log(f"túnel {name} desativado")

    def activate(self, name):
        with self.lock:
            self.validate(self.read(name))
            for other in self.active():
                if other != name:
                    self._down(other)
            if name not in self._up_set():
                self._up(name)
            self.settings["active"] = name
            self.save_settings()

    def deactivate(self, name, remember=False):
        with self.lock:
            self.read(name)
            if name in self._up_set():
                self._down(name)
            if not remember and self.settings.get("active") == name:
                self.settings["active"] = None
                self.save_settings()

    # -- edição

    def create(self, name, text, killswitch=False):
        with self.lock:
            check_name(name)
            if self.exists(name):
                raise ConfigError(f"já existe um túnel chamado '{name}'")
            self.validate(text)
            self._write(name, text)
            self.settings["killswitch"][name] = bool(killswitch)
            self.save_settings()
            log(f"túnel {name} criado")

    def update(self, old, new, text, killswitch=False):
        with self.lock:
            self.read(old)
            check_name(new)
            if new != old and self.exists(new):
                raise ConfigError(f"já existe um túnel chamado '{new}'")
            self.validate(text)
            was_active = old in self._up_set()
            if was_active:
                self._down(old)
            self._write(new, text)
            if new != old:
                os.remove(self.path(old))
                self.settings["killswitch"].pop(old, None)
                if self.settings.get("active") == old:
                    self.settings["active"] = new
            self.settings["killswitch"][new] = bool(killswitch)
            self.save_settings()
            log(f"túnel {old} salvo" + (f" como {new}" if new != old else ""))
            if was_active:
                self._up(new)

    def delete(self, name):
        with self.lock:
            self.read(name)
            if name in self._up_set():
                self._down(name)
            os.remove(self.path(name))
            self.settings["killswitch"].pop(name, None)
            if self.settings.get("active") == name:
                self.settings["active"] = None
            self.save_settings()
            log(f"túnel {name} excluído")

    def import_files(self, files):
        """files: lista de (nome_do_arquivo, bytes). Aceita .conf e .zip com .conf dentro."""
        entries, errors = [], []
        for fname, data in files:
            if fname.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        for info in z.infolist()[:200]:
                            if info.is_dir() or not info.filename.lower().endswith(".conf"):
                                continue
                            with z.open(info) as fh:
                                content = fh.read(self.MAX_IMPORT_FILE + 1)
                            entries.append((info.filename, content))
                except zipfile.BadZipFile:
                    errors.append(f"{fname}: arquivo zip inválido")
            else:
                entries.append((fname, data))

        imported = []
        with self.lock:
            for fname, data in entries:
                base = os.path.basename(fname.replace("\\", "/"))
                stem = base[:-5] if base.lower().endswith(".conf") else base
                try:
                    if len(data) > self.MAX_IMPORT_FILE:
                        raise ConfigError("arquivo grande demais")
                    try:
                        text = data.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        raise ConfigError("o arquivo não é texto UTF-8")
                    self.validate(text)
                    name = self._unique(_sanitize(stem))
                    self._write(name, text)
                    self.settings["killswitch"][name] = False
                    imported.append(name)
                    log(f"túnel {name} importado de {base}")
                except ConfigError as e:
                    errors.append(f"{base}: {e}")
            self.save_settings()
        return {"imported": imported, "errors": errors}

    def export_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n in self.names():
                z.writestr(n + ".conf", self.read(n))
        return buf.getvalue()

    # -- ciclo de vida do contêiner

    def startup(self):
        with self.lock:
            self.backend.killswitch_off()
            name = self.settings.get("active")
            up = self._up_set()
            if not (name and name in up):
                self.backend.restore_dns()
            if not name or not self.exists(name):
                return
            try:
                if name in up:
                    log(f"túnel {name} já estava ativo")
                    self.backend.down(self.path(name))
                self._up(name)
            except (WgError, ConfigError) as e:
                log(f"não foi possível restaurar o túnel {name}: {e}")

    def shutdown(self):
        with self.lock:
            for name in self.active():
                try:
                    self._down(name)
                except WgError as e:
                    log(f"erro ao desativar {name}: {e}")
