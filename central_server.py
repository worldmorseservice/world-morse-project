#!/usr/bin/env python3
# central_server.py
# WorldMorse Minimal Central (Render-ready)

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ---- paths ----
SERVER_KEY_PATH = "central_signing_key_p256.pem"  # local fallback
SECRET_KEY_FILE = "/etc/secrets/central_signing_key_p256.pem"  # Render Secret File
REGISTRY_PATH = "registry.json"  # stored on ephemeral disk in Render free (OK for prototype)

TOKEN_ISSUER = "worldmorse"
TOKEN_TTL_SEC = 300  # 5 minutes

PRESENCE_TTL_SEC = 60
SIGNAL_TTL_SEC = 300


def now_ms() -> int:
    return int(time.time() * 1000)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def load_or_create_server_key() -> ec.EllipticCurvePrivateKey:
    # 1) Render Secret File
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise RuntimeError("invalid secret key type")
            return key

    # 2) Local persisted file
    if os.path.exists(SERVER_KEY_PATH):
        with open(SERVER_KEY_PATH, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise RuntimeError("invalid local key type")
            return key

    # 3) Create local key
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(pem)
    return key


def pubkey_to_jwk(pub: ec.EllipticCurvePublicKey, kid: str = "k1") -> Dict[str, Any]:
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")
    return {"kid": kid, "kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y)}


def jwk_to_pubkey(jwk: Dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Only EC P-256 supported")
    x = int.from_bytes(b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify_ecdsa_sig(pub: ec.EllipticCurvePublicKey, msg: bytes, sig_b64u: str) -> bool:
    """
    Browser side sends raw signature = r||s (64 bytes), base64url.
    Convert to DER and verify.
    """
    try:
        sig = b64u_decode(sig_b64u)
        if len(sig) != 64:
            return False
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = encode_dss_signature(r, s)
        pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def load_registry() -> Dict[str, Any]:
    if not os.path.exists(REGISTRY_PATH):
        return {"callsigns": {}}
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_registry(reg: Dict[str, Any]) -> None:
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=2)


@dataclass
class PresenceItem:
    callsign: str
    peer_id: str
    last_seen_ms: int


@dataclass
class Session:
    session_id: str
    room_id: str
    from_peer_id: str
    to_peer_id: str
    expires_ms: int
    queues: Dict[str, List[Dict[str, Any]]]  # events per peer


server_key = load_or_create_server_key()
server_pub_jwk = pubkey_to_jwk(server_key.public_key(), kid="k1")

app = FastAPI(title="WorldMorse Minimal Central", version="1.0")

# CORS (prototype)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static hosting: /static/peer_client.html
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static", html=True), name="static")

presence: Dict[str, Dict[str, PresenceItem]] = {}  # room_id -> peer_id -> PresenceItem
sessions: Dict[str, Session] = {}
inbox: Dict[str, List[str]] = {}  # to_peer_id -> [session_id, ...]


def cleanup() -> None:
    now = now_ms()
    for room_id in list(presence.keys()):
        for pid in list(presence[room_id].keys()):
            if now - presence[room_id][pid].last_seen_ms > PRESENCE_TTL_SEC * 1000:
                del presence[room_id][pid]
        if not presence[room_id]:
            del presence[room_id]
    for sid in list(sessions.keys()):
        if now > sessions[sid].expires_ms:
            del sessions[sid]
    for to_pid in list(inbox.keys()):
        inbox[to_pid] = [sid for sid in inbox[to_pid] if sid in sessions]
        if not inbox[to_pid]:
            del inbox[to_pid]


def verify_token(token: str, room_id: Optional[str] = None) -> Dict[str, Any]:
    try:
        pub = jwk_to_pubkey(server_pub_jwk)
        payload = jwt.decode(
            token,
            pub,
            algorithms=["ES256"],
            options={"require": ["exp", "iat", "iss", "sub", "jti"]},
            issuer=TOKEN_ISSUER,
        )
        if room_id is not None and payload.get("room") != room_id:
            raise HTTPException(status_code=401, detail="wrong_room")
        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")


class RegisterReq(BaseModel):
    callsign: str = Field(min_length=3, max_length=6)
    public_key_jwk: Dict[str, Any]
    nonce: str
    signature_b64u: str


class TokenIssueReq(BaseModel):
    callsign: str
    room_id: str
    peer_id: str
    nonce: str
    signature_b64u: str


class PresenceUpsertReq(BaseModel):
    peer_id: str
    callsign: str


class SessionCreateReq(BaseModel):
    room_id: str
    from_peer_id: str
    to_peer_id: str


class SDPPostReq(BaseModel):
    from_peer_id: str
    sdp: str


class ICEPostReq(BaseModel):
    from_peer_id: str
    candidate: str
    sdpMid: str
    sdpMLineIndex: int


@app.get("/v1/meta")
def get_meta() -> Dict[str, Any]:
    cleanup()
    return {
        "service": "worldmorse-minimal-central",
        "version": "1.0",
        "token_verify_keys": [server_pub_jwk],
        "time_ms": now_ms(),
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "time_ms": now_ms()}


@app.post("/v1/registry/register")
def registry_register(req: RegisterReq) -> Dict[str, Any]:
    cleanup()
    reg = load_registry()
    callsigns: Dict[str, Any] = reg.get("callsigns", {})

    if req.callsign in callsigns:
        raise HTTPException(status_code=409, detail="callsign_taken")

    pub = jwk_to_pubkey(req.public_key_jwk)
    msg = f"register|{req.callsign}|{req.nonce}".encode("utf-8")
    if not verify_ecdsa_sig(pub, msg, req.signature_b64u):
        raise HTTPException(status_code=400, detail="invalid_signature")

    callsigns[req.callsign] = {"public_key_jwk": req.public_key_jwk}
    reg["callsigns"] = callsigns
    save_registry(reg)
    return {"ok": True}


@app.get("/v1/registry/lookup")
def registry_lookup(callsign: str) -> Dict[str, Any]:
    cleanup()
    reg = load_registry()
    callsigns = reg.get("callsigns", {})
    if callsign not in callsigns:
        raise HTTPException(status_code=404, detail="not_found")
    return {"callsign": callsign, "public_key_jwk": callsigns[callsign]["public_key_jwk"]}


@app.post("/v1/token/issue")
def token_issue(req: TokenIssueReq) -> Dict[str, Any]:
    cleanup()
    reg = load_registry()
    callsigns = reg.get("callsigns", {})
    if req.callsign not in callsigns:
        raise HTTPException(status_code=404, detail="callsign_not_registered")

    pub = jwk_to_pubkey(callsigns[req.callsign]["public_key_jwk"])
    msg = f"issue|{req.callsign}|{req.room_id}|{req.peer_id}|{req.nonce}".encode("utf-8")
    if not verify_ecdsa_sig(pub, msg, req.signature_b64u):
        raise HTTPException(status_code=400, detail="invalid_signature")

    iat = int(time.time())
    exp = iat + TOKEN_TTL_SEC
    jti = str(uuid.uuid4())
    payload = {
        "iss": TOKEN_ISSUER,
        "sub": req.callsign,
        "room": req.room_id,
        "peer": req.peer_id,
        "iat": iat,
        "exp": exp,
        "jti": jti,
    }
    token = jwt.encode(payload, server_key, algorithm="ES256", headers={"kid": "k1"})
    return {"token": token, "exp_ms": TOKEN_TTL_SEC * 1000}


@app.post("/v1/rooms/{room_id}/presence/upsert")
def presence_upsert(room_id: str, req: PresenceUpsertReq, authorization: str = Header(default="")) -> Dict[str, Any]:
    cleanup()
    bearer = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(bearer, room_id=room_id)

    if payload.get("sub") != req.callsign or payload.get("peer") != req.peer_id:
        raise HTTPException(status_code=401, detail="token_mismatch")

    presence.setdefault(room_id, {})
    presence[room_id][req.peer_id] = PresenceItem(
        callsign=req.callsign,
        peer_id=req.peer_id,
        last_seen_ms=now_ms(),
    )
    return {"ok": True, "ttl_ms": PRESENCE_TTL_SEC * 1000}


@app.get("/v1/rooms/{room_id}/presence")
def presence_list(room_id: str) -> Dict[str, Any]:
    cleanup()
    peers = []
    for item in presence.get(room_id, {}).values():
        peers.append({"callsign": item.callsign, "peer_id": item.peer_id, "last_seen_ms": item.last_seen_ms})
    peers.sort(key=lambda x: x["callsign"])
    return {"room_id": room_id, "peers": peers}


@app.post("/v1/webrtc/session/create")
def session_create(req: SessionCreateReq, authorization: str = Header(default="")) -> Dict[str, Any]:
    cleanup()
    bearer = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(bearer, room_id=req.room_id)
    if payload.get("peer") != req.from_peer_id:
        raise HTTPException(status_code=401, detail="token_mismatch")

    session_id = str(uuid.uuid4())
    expires_ms = now_ms() + SIGNAL_TTL_SEC * 1000
    sess = Session(
        session_id=session_id,
        room_id=req.room_id,
        from_peer_id=req.from_peer_id,
        to_peer_id=req.to_peer_id,
        expires_ms=expires_ms,
        queues={req.from_peer_id: [], req.to_peer_id: []},
    )
    sessions[session_id] = sess
    inbox.setdefault(req.to_peer_id, []).append(session_id)
    return {"session_id": session_id, "ttl_ms": SIGNAL_TTL_SEC * 1000}


@app.get("/v1/webrtc/inbox")
def webrtc_inbox(peer_id: str) -> Dict[str, Any]:
    cleanup()
    return {"peer_id": peer_id, "sessions": inbox.get(peer_id, [])}


def push_event(session_id: str, from_peer_id: str, ev: Dict[str, Any]) -> None:
    sess = sessions.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="session_not_found")
    if from_peer_id not in sess.queues:
        raise HTTPException(status_code=403, detail="not_in_session")
    other = sess.to_peer_id if from_peer_id == sess.from_peer_id else sess.from_peer_id
    sess.queues[other].append(ev)


@app.post("/v1/webrtc/session/{session_id}/offer")
def webrtc_offer(session_id: str, req: SDPPostReq, authorization: str = Header(default="")) -> Dict[str, Any]:
    cleanup()
    bearer = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(bearer)
    if payload.get("peer") != req.from_peer_id:
        raise HTTPException(status_code=401, detail="token_mismatch")
    push_event(session_id, req.from_peer_id, {"type": "offer", "sdp": req.sdp})
    return {"ok": True}


@app.post("/v1/webrtc/session/{session_id}/answer")
def webrtc_answer(session_id: str, req: SDPPostReq, authorization: str = Header(default="")) -> Dict[str, Any]:
    cleanup()
    bearer = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(bearer)
    if payload.get("peer") != req.from_peer_id:
        raise HTTPException(status_code=401, detail="token_mismatch")
    push_event(session_id, req.from_peer_id, {"type": "answer", "sdp": req.sdp})
    return {"ok": True}


@app.post("/v1/webrtc/session/{session_id}/ice")
def webrtc_ice(session_id: str, req: ICEPostReq, authorization: str = Header(default="")) -> Dict[str, Any]:
    cleanup()
    bearer = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(bearer)
    if payload.get("peer") != req.from_peer_id:
        raise HTTPException(status_code=401, detail="token_mismatch")
    push_event(
        session_id,
        req.from_peer_id,
        {"type": "ice", "candidate": req.candidate, "sdpMid": req.sdpMid, "sdpMLineIndex": req.sdpMLineIndex},
    )
    return {"ok": True}


@app.get("/v1/webrtc/session/{session_id}/poll")
def webrtc_poll(session_id: str, peer_id: str, cursor: int = 0, authorization: str = Header(default="")) -> Dict[str, Any]:
    cleanup()
    bearer = authorization.removeprefix("Bearer ").strip()
    payload = verify_token(bearer)
    if payload.get("peer") != peer_id:
        raise HTTPException(status_code=401, detail="token_mismatch")

    sess = sessions.get(session_id)
    if not sess or peer_id not in sess.queues:
        raise HTTPException(status_code=404, detail="session_not_found")

    q = sess.queues[peer_id]
    if cursor < 0 or cursor > len(q):
        cursor = 0
    events = q[cursor:]
    next_cursor = len(q)
    return {"events": events, "next_cursor": next_cursor}
