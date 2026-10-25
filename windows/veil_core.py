#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ядро клиента Veil для Windows/Linux/macOS: криптография, протокол, транспорт.

GUI-независимо и полностью покрывается headless-тестами
(tests/windows_client_e2e.py). Протокол бит-в-бит совместим с macOS-клиентом
(macos/Veil/Sources/Crypto.swift):

  - идентичность:  Ed25519 (подписи) + X25519 (ECDH)
  - ключи направлений: HKDF-SHA256, salt "VEIL-SALT-V1",
    info "VEIL-CTX-V1:<lo>:<hi>" (стороны сортируются по sign-ключу),
    сторона с меньшим ключом шифрует первыми 32 байтами HKDF
  - конверт: ChaCha20-Poly1305, payload = nonce(12)||ct||tag, base64
  - подпись конверта: Ed25519 над raw32(X25519-пуб отправителя)||payload
  - аутентификация к relay: Ed25519 над "<purpose>:<user>:<ts>:<nonce>"
  - файл личности: camelCase-JSON (signPriv/signPub/xPriv/xPub/createdAt) —
    совместим с резервной копией macOS-клиента

Зависимости: cryptography (обязательно), websocket-client (опционально:
без неё клиент работает только через polling).
"""

import base64
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

try:
    import websocket  # websocket-client
    HAVE_WS = True
except ImportError:
    HAVE_WS = False

KDF_SALT = b"VEIL-SALT-V1"
KDF_INFO_PREFIX = "VEIL-CTX-V1"
INVITE_PREFIX = "veil-invite:v1:"


# ------------------------------------------------------------------ утилиты

def hkdf_sha256(ikm, salt, info, length):
    """HKDF-SHA256 (RFC 5869); совпадает с CryptoKit hkdfDerivedSymmetricKey."""
    import hashlib
    import hmac
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def is_hex64(s):
    return isinstance(s, str) and len(s) == 64 \
        and all(c in "0123456789abcdef" for c in s.lower())


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def now_ms():
    return time.time() * 1000.0


def normalize_base(raw):
    s = (raw or "").strip()
    if not s.startswith(("http://", "https://")):
        s = "https://" + s
    return s.rstrip("/")


def ws_url(base):
    s = normalize_base(base)
    if s.startswith("https://"):
        s = "wss://" + s[len("https://"):]
    elif s.startswith("http://"):
        s = "ws://" + s[len("http://"):]
    return s + "/api/v1/ws"


def default_state_dir():
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return os.path.join(appdata, "Veil")
        return os.path.join(os.path.expanduser("~"), "Veil")
    if sys.platform == "darwin":
        # отдельный каталог, чтобы не пересекаться с macOS-приложением
        # (формат store.json у Swift- и python-клиентов разный)
        return os.path.expanduser(
            "~/Library/Application Support/VeilPython")
    return os.path.expanduser("~/.local/share/Veil")


# ------------------------------------------------------------------ личность

class VeilIdentity:
    def __init__(self, sign_priv, x_priv):
        """sign_priv/x_priv: bytes (32)."""
        self.sign = Ed25519PrivateKey.from_private_bytes(sign_priv)
        self.x = X25519PrivateKey.from_private_bytes(x_priv)

    @classmethod
    def generate(cls):
        return cls(os.urandom(32), os.urandom(32))

    @property
    def sign_pub_hex(self):
        return self.sign.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()

    @property
    def x_pub_hex(self):
        return self.x.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw).hex()

    def to_keys_dict(self):
        """Формат файла личности — идентичен экспорту macOS-клиента."""
        return {
            "signPriv": self.sign.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            "signPub": self.sign_pub_hex,
            "xPriv": self.x.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            "xPub": self.x_pub_hex,
            "createdAt": now_ms() / 1000.0,
        }

    @classmethod
    def from_keys_dict(cls, d):
        try:
            ident = cls(bytes.fromhex(d["signPriv"]), bytes.fromhex(d["xPriv"]))
        except (KeyError, ValueError, TypeError):
            return None
        if ident.sign_pub_hex != str(d.get("signPub", "")).lower():
            return None
        if ident.x_pub_hex != str(d.get("xPub", "")).lower():
            return None
        return ident


# ------------------------------------------------------------------ крипто

def conversation_keys(my_x_priv_bytes, peer_x_pub_hex, my_sign_pub, peer_sign_pub):
    """(send, receive) ключи ChaCha20-Poly1305 для переписки с peer."""
    shared = X25519PrivateKey.from_private_bytes(my_x_priv_bytes).exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(peer_x_pub_hex)))
    lo, hi = sorted([my_sign_pub, peer_sign_pub])
    info = ("%s:%s:%s" % (KDF_INFO_PREFIX, lo, hi)).encode()
    okm = hkdf_sha256(shared, KDF_SALT, info, 64)
    if lo == hi:  # самопереписка («Избранное»)
        return okm[:32], okm[:32]
    return (okm[:32], okm[32:]) if my_sign_pub == lo else (okm[32:], okm[:32])


def seal(plaintext, key):
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def unseal(payload, key):
    return ChaCha20Poly1305(key).decrypt(payload[:12], payload[12:], None)


def envelope_signature(x_pub_hex, payload, sign_key):
    return sign_key.sign(bytes.fromhex(x_pub_hex) + payload)


def verify_envelope_signature(sig, sender_x_pub_hex, sender_sign_pub_hex, payload):
    if not is_hex64(sender_x_pub_hex) or not is_hex64(sender_sign_pub_hex):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(sender_sign_pub_hex)).verify(
            sig, bytes.fromhex(sender_x_pub_hex) + payload)
        return True
    except Exception:
        return False


def auth_headers(identity, purpose="inbox"):
    ts = int(time.time())
    nonce = os.urandom(8).hex()
    msg = ("%s:%s:%d:%s" % (purpose, identity.sign_pub_hex, ts, nonce)).encode()
    sig = identity.sign.sign(msg)
    return {
        "X-Veil-User": identity.sign_pub_hex,
        "X-Veil-Timestamp": str(ts),
        "X-Veil-Nonce": nonce,
        "X-Veil-Signature": base64.b64encode(sig).decode(),
    }


# ------------------------------------------------------------------ приглашения

def encode_invite(name, sign_pub_hex, x_pub_hex, relays):
    payload = {"v": 1, "n": name, "s": sign_pub_hex,
               "x": x_pub_hex, "r": relays}
    return INVITE_PREFIX + b64url_encode(
        json.dumps(payload, ensure_ascii=False,
                   separators=(",", ":")).encode("utf-8"))


def parse_invite(raw):
    s = (raw or "").strip()
    if INVITE_PREFIX in s:
        s = s.split(INVITE_PREFIX, 1)[1]
    try:
        payload = json.loads(b64url_decode(s.strip()).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return None
    if not is_hex64(payload.get("s", "")) or not is_hex64(payload.get("x", "")):
        return None
    payload["r"] = [normalize_base(u) for u in payload.get("r", [])
                    if isinstance(u, str) and u.strip()]
    return payload


# ------------------------------------------------------------------ состояние

class ClientState:
    """JSON-файл со всем состоянием (права 0600, где поддерживается)."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {
            "identity": None,          # keys_dict или None
            "profileName": "",
            "contacts": [],            # {signPub, name, xPub, relays, addedAt, lastMessageAt}
            "messages": [],            # {id, contactId, incoming, text, ts, delivered, remoteId}
            "relays": [],              # {url, enabled}
        }
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            for key in self.data:
                if key in loaded:
                    self.data[key] = loaded[key]
        except (OSError, ValueError):
            pass

    def save(self):
        with self.lock:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=1)
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)

    # --- helpers ---
    @property
    def identity(self):
        d = self.data.get("identity")
        return VeilIdentity.from_keys_dict(d) if d else None

    def set_identity(self, identity, name):
        self.data["identity"] = identity.to_keys_dict()
        self.data["profileName"] = name or "Я"
        self.save()

    def contact(self, sign_pub):
        for c in self.data["contacts"]:
            if c["signPub"] == sign_pub:
                return c
        return None

    def add_contact_from_invite(self, inv):
        s = inv["s"].lower()
        if self.data.get("identity") and s == self.data["identity"]["signPub"]:
            return False
        existing = self.contact(s)
        if existing:
            if not existing.get("relays") and inv.get("r"):
                existing["relays"] = inv["r"]
            self.save()
            return True
        self.data["contacts"].append({
            "signPub": s,
            "name": inv.get("n") or ("Контакт · " + s[:8]),
            "xPub": inv["x"].lower(),
            "relays": inv.get("r", []),
            "addedAt": time.time(),
            "lastMessageAt": None,
        })
        self.save()
        return True

    def enabled_relay_urls(self):
        return [normalize_base(r["url"]) for r in self.data["relays"]
                if r.get("enabled", True)]

    def add_relay(self, raw_url):
        base = normalize_base(raw_url)
        if len(base) < len("https://x.x"):
            return False
        for r in self.data["relays"]:
            if normalize_base(r["url"]) == base:
                return True
        self.data["relays"].append({"url": base, "enabled": True})
        self.save()
        return True

    def remove_relay(self, base):
        self.data["relays"] = [
            r for r in self.data["relays"] if normalize_base(r["url"]) != base]
        self.save()


# ------------------------------------------------------------------ транспорт

class RelayTransport:
    """REST-клиент relay (urllib, без зависимостей)."""

    TIMEOUT = 12

    @staticmethod
    def post_envelope(base, envelope):
        url = normalize_base(base) + "/api/v1/envelopes"
        body = json.dumps(envelope).encode("utf-8")
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=RelayTransport.TIMEOUT) as r:
                return 200 <= r.status < 300
        except (urllib.error.URLError, OSError, ValueError):
            return False

    @staticmethod
    def fetch_inbox(base, identity):
        """Список конвертов или None при ошибке сети/авторизации."""
        url = normalize_base(base) + "/api/v1/inbox"
        req = urllib.request.Request(url, method="GET",
                                     headers=auth_headers(identity, "inbox"))
        try:
            with urllib.request.urlopen(req, timeout=RelayTransport.TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8")).get("envelopes", [])
        except (urllib.error.URLError, OSError, ValueError):
            return None

    @staticmethod
    def health(base):
        url = normalize_base(base) + "/health"
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status == 200
        except (urllib.error.URLError, OSError):
            return False


# ------------------------------------------------------------------ ядро клиента

class VeilClientCore:
    """Склейка состояния, криптографии и фоновых потоков доставки.

    События (callback(event_type, payload)) появляются из фоновых потоков:
      message  — новое входящее/исходящее сообщение
      delivery — статус доставки исходящего
      contact  — добавлен/обновлён контакт
      sync     — завершился цикл опроса relay
      error    — текст ошибки для пользователя
    """

    POLL_MIN_S = 4.0
    POLL_JITTER_S = 5.0

    def __init__(self, state, on_event=None):
        self.state = state
        self.on_event = on_event
        self._stop = threading.Event()
        self._poll_thread = None
        self._ws_threads = {}

    # --- события ---
    def _emit(self, kind, payload=None):
        if self.on_event:
            try:
                self.on_event(kind, payload)
            except Exception:
                pass

    # --- жизненный цикл ---
    def start(self):
        self._stop.clear()
        self._poll_thread = threading.Thread(
            target=self._poll_loop, name="veil-poll", daemon=True)
        self._poll_thread.start()
        self._start_ws_threads()

    def stop(self):
        self._stop.set()

    def _start_ws_threads(self):
        if not HAVE_WS:
            return
        for base in self.state.enabled_relay_urls():
            if base not in self._ws_threads:
                t = threading.Thread(target=self._ws_loop, args=(base,),
                                     name="veil-ws-" + base, daemon=True)
                t.start()
                self._ws_threads[base] = t

    # --- отправка ---
    def build_envelope(self, identity, text, msg_id, to_sign_pub, to_x_pub):
        send_key, _ = conversation_keys(
            identity.x.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                     NoEncryption()),
            to_x_pub, identity.sign_pub_hex, to_sign_pub)
        inner = {"i": msg_id, "t": text, "ts": now_ms(),
                 "r": self.state.enabled_relay_urls()}
        plaintext = json.dumps(inner, ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8")
        payload = seal(plaintext, send_key)
        sig = envelope_signature(identity.x_pub_hex, payload, identity.sign)
        return {
            "to": to_sign_pub,
            "from": identity.sign_pub_hex,
            "from_x": identity.x_pub_hex,
            "payload": base64.b64encode(payload).decode(),
            "sig": base64.b64encode(sig).decode(),
        }

    def send_message(self, text, to_sign_pub):
        """Синхронная отправка (вызывать из рабочего потока). True — доставлено."""
        text = (text or "").strip()
        identity = self.state.identity
        if not identity or not text:
            return False
        is_self = to_sign_pub == identity.sign_pub_hex
        contact = None if is_self else self.state.contact(to_sign_pub)
        if is_self:
            to_x_pub = identity.x_pub_hex
        elif contact:
            to_x_pub = contact["xPub"]
        else:
            self._emit("error", "Контакт не найден")
            return False

        msg_id = "%s" % uuid4_hex()
        envelope = self.build_envelope(identity, text, msg_id,
                                       to_sign_pub, to_x_pub)
        self.state.data["messages"].append({
            "id": msg_id, "contactId": to_sign_pub, "incoming": False,
            "text": text, "ts": now_ms(), "delivered": False,
            "remoteId": msg_id})
        self.state.save()
        self._emit("message", to_sign_pub)

        targets = ([normalize_base(u) for u in contact["relays"]]
                   if contact and contact.get("relays")
                   else self.state.enabled_relay_urls())
        if not targets:
            self._emit("error", "Не настроен ни один relay — добавьте его в настройках")
            return False
        delivered = any(RelayTransport.post_envelope(b, envelope) for b in targets)
        self._mark_delivery(msg_id, delivered)
        return delivered

    def _mark_delivery(self, msg_id, delivered):
        for m in self.state.data["messages"]:
            if m["remoteId"] == msg_id and not m["incoming"]:
                m["delivered"] = delivered
        self.state.save()
        self._emit("delivery", msg_id)

    # --- приём ---
    def handle_envelope(self, env):
        """Обработка одного конверта. Возвращает тип события или None."""
        identity = self.state.identity
        if not identity:
            return None
        try:
            sender = str(env.get("sender", "")).lower()
            sender_x = str(env.get("sender_x", "")).lower()
            payload = base64.b64decode(env.get("payload", ""))
            sig = base64.b64decode(env.get("sig", ""))
        except Exception:
            return None
        if not is_hex64(sender) or not is_hex64(sender_x):
            return None

        if not verify_envelope_signature(sig, sender_x, sender, payload):
            return None

        x_priv = identity.x.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                          NoEncryption())
        _, recv_key = conversation_keys(x_priv, sender_x,
                                        identity.sign_pub_hex, sender)
        try:
            plaintext = unseal(payload, recv_key)
        except InvalidTag:
            return None
        try:
            inner = json.loads(plaintext.decode("utf-8"))
        except ValueError:
            return None

        is_self = sender == identity.sign_pub_hex
        chat_id = identity.sign_pub_hex if is_self else sender

        # дедупликация (WS push + polling)
        for m in self.state.data["messages"]:
            if m["remoteId"] == inner.get("i") and m["contactId"] == chat_id:
                if not m["incoming"]:
                    m["delivered"] = True
                    self.state.save()
                    self._emit("delivery", inner.get("i"))
                return "delivery"

        if not is_self:
            contact = self.state.contact(sender)
            if contact is None:
                self.state.data["contacts"].append({
                    "signPub": sender,
                    "name": "Неизвестный · " + sender[:8],
                    "xPub": sender_x,
                    "relays": inner.get("r", []),
                    "addedAt": time.time(),
                    "lastMessageAt": inner.get("ts"),
                })
                self._emit("contact", sender)
            else:
                if contact["xPub"] != sender_x:
                    contact["xPub"] = sender_x
                if not contact.get("relays") and inner.get("r"):
                    contact["relays"] = inner["r"]
                contact["lastMessageAt"] = inner.get("ts")

        self.state.data["messages"].append({
            "id": uuid4_hex(), "contactId": chat_id,
            "incoming": not is_self, "text": inner.get("t", ""),
            "ts": inner.get("ts", now_ms()), "delivered": True,
            "remoteId": inner.get("i")})
        if is_self:
            for m in self.state.data["messages"]:
                if m["remoteId"] == inner.get("i") and not m["incoming"]:
                    m["delivered"] = True
        self.state.save()
        self._emit("message", chat_id)
        return "message"

    # --- фоновые потоки ---
    def _poll_loop(self):
        while not self._stop.is_set():
            delay = 6.0
            identity = self.state.identity
            if identity:
                bases = self.state.enabled_relay_urls()
                if bases:
                    for base in bases:
                        if self._stop.is_set():
                            break
                        envelopes = RelayTransport.fetch_inbox(base, identity)
                        if envelopes:
                            for env in envelopes:
                                self.handle_envelope(env)
                    self._emit("sync", None)
                    delay = self.POLL_MIN_S + random.uniform(0, self.POLL_JITTER_S)
            self._stop.wait(delay)

    def _ws_loop(self, base):
        url = ws_url(base)
        identity = self.state.identity
        if not identity:
            return
        while not self._stop.is_set():
            try:
                ws = websocket.create_connection(url, timeout=10)
                ws.settimeout(10)
                ts = int(time.time())
                nonce = os.urandom(8).hex()
                frame = {"type": "auth", "user": identity.sign_pub_hex,
                         "ts": ts, "nonce": nonce}
                frame["signature"] = base64.b64encode(identity.sign.sign(
                    ("ws:%s:%d:%s" % (identity.sign_pub_hex, ts, nonce)).encode())).decode()
                ws.send(json.dumps(frame))
                greeting = json.loads(ws.recv())
                if greeting.get("type") != "ready":
                    ws.close()
                    raise ValueError("relay отверг авторизацию")
                ws.settimeout(None)
                self._emit("sync", None)
                while not self._stop.is_set():
                    raw = ws.recv()
                    if not raw:
                        break
                    frame = json.loads(raw)
                    if frame.get("type") == "envelope":
                        self.handle_envelope(frame.get("envelope", {}))
            except Exception:
                pass
            self._stop.wait(5 + random.uniform(0, 8))


def uuid4_hex():
    import uuid
    return uuid.uuid4().hex


# ------------------------------------------------------------------ selftest

def _selftest():
    passed, failed = 0, 0

    def check(name, cond):
        nonlocal passed, failed
        print(("  ok   " if cond else "  FAIL ") + name)
        passed, failed = passed + (1 if cond else 0), failed + (0 if cond else 1)

    a, b = VeilIdentity.generate(), VeilIdentity.generate()
    check("identity: ключи 64 hex", is_hex64(a.sign_pub_hex) and is_hex64(a.x_pub_hex))

    d = a.to_keys_dict()
    check("identity: формат файла как у macOS (camelCase)",
          set(d) == {"signPriv", "signPub", "xPriv", "xPub", "createdAt"})
    check("identity: roundtrip", VeilIdentity.from_keys_dict(d).sign_pub_hex == a.sign_pub_hex)
    broken = dict(d, signPub=b.sign_pub_hex)
    check("identity: несовпадение ключей отклоняется", VeilIdentity.from_keys_dict(broken) is None)

    inv = encode_invite("Тест", b.sign_pub_hex, b.x_pub_hex, ["https://r.example.com"])
    parsed = parse_invite(inv)
    check("invite: roundtrip", parsed and parsed["s"] == b.sign_pub_hex)
    check("invite: мусор отклоняется", parse_invite("не-invite") is None)

    a_x = a.x.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    b_x = b.x.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    a_send, a_recv = conversation_keys(a_x, b.x_pub_hex, a.sign_pub_hex, b.sign_pub_hex)
    b_send, b_recv = conversation_keys(b_x, a.x_pub_hex, b.sign_pub_hex, a.sign_pub_hex)
    pt = "Привет от Windows-клиента! 🪟".encode("utf-8")
    check("шифрование A→B", unseal(seal(pt, a_send), b_recv) == pt)
    check("шифрование B→A", unseal(seal(pt, b_send), a_recv) == pt)
    bad = bytearray(seal(pt, a_send))
    bad[-1] ^= 0xFF
    try:
        unseal(bytes(bad), b_recv)
        check("подмена отклоняется AEAD", False)
    except InvalidTag:
        check("подмена отклоняется AEAD", True)
    s1, s2 = conversation_keys(a_x, a.x_pub_hex, a.sign_pub_hex, a.sign_pub_hex)
    check("Избранное: один ключ на оба направления", s1 == s2)

    payload = seal(pt, a_send)
    sig = envelope_signature(a.x_pub_hex, payload, a.sign)
    check("подпись конверта проверяется",
          verify_envelope_signature(sig, a.x_pub_hex, a.sign_pub_hex, payload))
    check("подпись конверта с чужим ключом отклоняется",
          not verify_envelope_signature(sig, b.x_pub_hex, a.sign_pub_hex, payload))

    print("selftest: %d passed, %d failed" % (passed, failed))
    return failed == 0


if __name__ == "__main__":
    import sys as _sys
    if "--selftest" in _sys.argv:
        _sys.exit(0 if _selftest() else 1)
    print("Это ядро клиента. GUI: python veil_client.py")
