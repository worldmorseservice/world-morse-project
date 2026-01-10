@echo off
chcp 65001 >nul
setlocal

cd /d C:\Users\user\worldmorse_net

echo [1/3] Writing requirements.txt
(
  echo fastapi==0.115.6
  echo uvicorn[standard]==0.34.0
  echo pyjwt==2.10.1
  echo cryptography==44.0.0
) > requirements.txt

echo [2/3] Writing central_server.py
(
  echo #!/usr/bin/env python3
  echo # central_server.py
  echo # WorldMorse Minimal Central v1 (prototype^)
  echo #
  echo # Run:
  echo #   cd C:\Users\user\worldmorse_net
  echo #   python central_server.py
  echo #
  echo # Static:
  echo #   http://127.0.0.1:8080/static/peer_client.html
  echo
  echo from __future__ import annotations
  echo
  echo import base64
  echo import json
  echo import os
  echo import time
  echo import uuid
  echo from dataclasses import dataclass
  echo from typing import Any, Dict, List, Optional
  echo
  echo import jwt
  echo from cryptography.hazmat.primitives import hashes
  echo from cryptography.hazmat.primitives.asymmetric import ec
  echo from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
  echo from cryptography.hazmat.primitives.serialization import ^(
  echo     Encoding,
  echo     NoEncryption,
  echo     PrivateFormat,
  echo     load_pem_private_key,
  echo ^)
  echo from fastapi import FastAPI, Header, HTTPException
  echo from fastapi.middleware.cors import CORSMiddleware
  echo from fastapi.staticfiles import StaticFiles
  echo from pydantic import BaseModel, Field
  echo
  echo SERVER_KEY_PATH = "central_signing_key_p256.pem"
  echo REGISTRY_PATH = "registry.json"
  echo
  echo TOKEN_ISSUER = "worldmorse"
  echo TOKEN_TTL_SEC = 300
  echo
  echo PRESENCE_TTL_SEC = 60
  echo SIGNAL_TTL_SEC = 300
  echo
  echo
  echo def now_ms^(^) -^> int:
  echo     return int^(time.time^(^) * 1000^)
  echo
  echo
  echo def b64u^(data: bytes^) -^> str:
  echo     return base64.urlsafe_b64encode^(data^).rstrip^(b"="^).decode^("ascii"^)
  echo
  echo
  echo def b64u_decode^(s: str^) -^> bytes:
  echo     pad = "=" * ^(^(^4 - ^(len^(s^) %% 4^)^) %% 4^)^)
  echo     return base64.urlsafe_b64decode^((s + pad^).encode^("ascii"^)^)
  echo
  echo
  echo def load_or_create_server_key^(^) -^> ec.EllipticCurvePrivateKey:
  echo     if os.path.exists^(SERVER_KEY_PATH^):
  echo         with open^(SERVER_KEY_PATH, "rb"^) as f:
  echo             return load_pem_private_key^(f.read^(^), password=None^)
  echo     key = ec.generate_private_key^(ec.SECP256R1^(^)^)
  echo     pem = key.private_bytes^(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption^(^)^)
  echo     with open^(SERVER_KEY_PATH, "wb"^) as f:
  echo         f.write^(pem^)
  echo     return key
  echo
  echo
  echo def pubkey_to_jwk^(pub: ec.EllipticCurvePublicKey, kid: str = "k1"^) -^> Dict[str, Any]:
  echo     nums = pub.public_numbers^(^)
  echo     x = nums.x.to_bytes^(32, "big"^)
  echo     y = nums.y.to_bytes^(32, "big"^)
  echo     return {"kid": kid, "kty": "EC", "crv": "P-256", "x": b64u^(x^), "y": b64u^(y^)}
  echo
  echo
  echo def jwk_to_pubkey^(jwk: Dict[str, Any]^) -^> ec.EllipticCurvePublicKey:
  echo     if jwk.get^("kty"^) != "EC" or jwk.get^("crv"^) != "P-256":
  echo         raise ValueError^("Only EC P-256 supported"^)
  echo     x = int.from_bytes^(b64u_decode^(jwk["x"]^), "big"^)
  echo     y = int.from_bytes^(b64u_decode^(jwk["y"]^), "big"^)
  echo     return ec.EllipticCurvePublicNumbers^(x, y, ec.SECP256R1^(^)^).public_key^(^)
  echo
  echo
  echo def verify_ecdsa_sig^(pub: ec.EllipticCurvePublicKey, msg: bytes, sig_b64u: str^) -^> bool:
  echo     try:
  echo         sig = b64u_decode^(sig_b64u^)
  echo         if len^(sig^) != 64:
  echo             return False
  echo         r = int.from_bytes^(sig[:32], "big"^)
  echo         s = int.from_bytes^(sig[32:], "big"^)
  echo         der = encode_dss_signature^(r, s^)
  echo         pub.verify^(der, msg, ec.ECDSA^(hashes.SHA256^(^)^)^)
  echo         return True
  echo     except Exception:
  echo         return False
  echo
  echo
  echo def load_registry^(^) -^> Dict[str, Any]:
  echo     if not os.path.exists^(REGISTRY_PATH^):
  echo         return {"callsigns": {}}
  echo     with open^(REGISTRY_PATH, "r", encoding="utf-8"^) as f:
  echo         return json.load^(f^)
  echo
  echo
  echo def save_registry^(reg: Dict[str, Any]^) -^> None:
  echo     with open^(REGISTRY_PATH, "w", encoding="utf-8"^) as f:
  echo         json.dump^(reg, f, ensure_ascii=False, indent=2^)
  echo
  echo
  echo @dataclass
  echo class PresenceItem:
  echo     callsign: str
  echo     peer_id: str
  echo     last_seen_ms: int
  echo
  echo
  echo @dataclass
  echo class Session:
  echo     session_id: str
  echo     room_id: str
  echo     from_peer_id: str
  echo     to_peer_id: str
  echo     expires_ms: int
  echo     queues: Dict[str, List[Dict[str, Any]]]
  echo
  echo
  echo server_key = load_or_create_server_key^(^)
  echo server_pub_jwk = pubkey_to_jwk^(server_key.public_key^(^), kid="k1"^)
  echo
  echo app = FastAPI^(title="WorldMorse Minimal Central", version="1.0"^)
  echo app.mount^("/static", StaticFiles^(directory=".", html=True^), name="static"^)
  echo
  echo app.add_middleware^(
  echo     CORSMiddleware,
  echo     allow_origins=["*"],
  echo     allow_credentials=False,
  echo     allow_methods=["*"],
  echo     allow_headers=["*"],
  echo ^)
  echo
  echo presence: Dict[str, Dict[str, PresenceItem]] = {}
  echo sessions: Dict[str, Session] = {}
  echo inbox: Dict[str, List[str]] = {}
  echo
  echo
  echo def cleanup^(^) -^> None:
  echo     now = now_ms^(^)
  echo     for room_id in list^(presence.keys^(^)^):
  echo         for pid in list^(presence[room_id].keys^(^)^):
  echo             if now - presence[room_id][pid].last_seen_ms ^> PRESENCE_TTL_SEC * 1000:
  echo                 del presence[room_id][pid]
  echo         if not presence[room_id]:
  echo             del presence[room_id]
  echo     for sid in list^(sessions.keys^(^)^):
  echo         if now ^> sessions[sid].expires_ms:
  echo             del sessions[sid]
  echo     for to_pid in list^(inbox.keys^(^)^):
  echo         inbox[to_pid] = [sid for sid in inbox[to_pid] if sid in sessions]
  echo         if not inbox[to_pid]:
  echo             del inbox[to_pid]
  echo
  echo
  echo def verify_token^(token: str, room_id: Optional[str] = None^) -^> Dict[str, Any]:
  echo     try:
  echo         pub = jwk_to_pubkey^(server_pub_jwk^)
  echo         payload = jwt.decode^(
  echo             token,
  echo             pub,
  echo             algorithms=["ES256"],
  echo             options={"require": ["exp", "iat", "iss", "sub", "jti"]},
  echo             issuer=TOKEN_ISSUER,
  echo         ^)
  echo         if room_id is not None and payload.get^("room"^) != room_id:
  echo             raise HTTPException^(status_code=401, detail="wrong_room"^)
  echo         return payload
  echo     except HTTPException:
  echo         raise
  echo     except Exception:
  echo         raise HTTPException^(status_code=401, detail="invalid_token"^)
  echo
  echo
  echo class RegisterReq^(BaseModel^):
  echo     callsign: str = Field^(min_length=3, max_length=6^)
  echo     public_key_jwk: Dict[str, Any]
  echo     nonce: str
  echo     signature_b64u: str
  echo
  echo
  echo class TokenIssueReq^(BaseModel^):
  echo     callsign: str
  echo     room_id: str
  echo     peer_id: str
  echo     nonce: str
  echo     signature_b64u: str
  echo
  echo
  echo class PresenceUpsertReq^(BaseModel^):
  echo     peer_id: str
  echo     callsign: str
  echo
  echo
  echo class SessionCreateReq^(BaseModel^):
  echo     room_id: str
  echo     from_peer_id: str
  echo     to_peer_id: str
  echo
  echo
  echo class SDPPostReq^(BaseModel^):
  echo     from_peer_id: str
  echo     sdp: str
  echo
  echo
  echo class ICEPostReq^(BaseModel^):
  echo     from_peer_id: str
  echo     candidate: str
  echo     sdpMid: str
  echo     sdpMLineIndex: int
  echo
  echo
  echo @app.get^("/v1/meta"^)
  echo def get_meta^(^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     return {"service": "worldmorse-minimal-central", "version": "1.0", "token_verify_keys": [server_pub_jwk], "time_ms": now_ms^(^)}
  echo
  echo
  echo @app.post^("/v1/registry/register"^)
  echo def registry_register^(req: RegisterReq^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     reg = load_registry^(^)
  echo     callsigns: Dict[str, Any] = reg.get^("callsigns", {}^)
  echo     if req.callsign in callsigns:
  echo         raise HTTPException^(status_code=409, detail="callsign_taken"^)
  echo     pub = jwk_to_pubkey^(req.public_key_jwk^)
  echo     msg = f"register|{req.callsign}|{req.nonce}".encode^("utf-8"^)
  echo     if not verify_ecdsa_sig^(pub, msg, req.signature_b64u^):
  echo         raise HTTPException^(status_code=400, detail="invalid_signature"^)
  echo     callsigns[req.callsign] = {"public_key_jwk": req.public_key_jwk}
  echo     reg["callsigns"] = callsigns
  echo     save_registry^(reg^)
  echo     return {"ok": True}
  echo
  echo
  echo @app.post^("/v1/token/issue"^)
  echo def token_issue^(req: TokenIssueReq^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     reg = load_registry^(^)
  echo     callsigns = reg.get^("callsigns", {}^)
  echo     if req.callsign not in callsigns:
  echo         raise HTTPException^(status_code=404, detail="callsign_not_registered"^)
  echo     pub = jwk_to_pubkey^(callsigns[req.callsign]["public_key_jwk"]^)
  echo     msg = f"issue|{req.callsign}|{req.room_id}|{req.peer_id}|{req.nonce}".encode^("utf-8"^)
  echo     if not verify_ecdsa_sig^(pub, msg, req.signature_b64u^):
  echo         raise HTTPException^(status_code=400, detail="invalid_signature"^)
  echo     iat = int^(time.time^(^)^)
  echo     exp = iat + TOKEN_TTL_SEC
  echo     jti = str^(uuid.uuid4^(^)^)
  echo     payload = {"iss": TOKEN_ISSUER, "sub": req.callsign, "room": req.room_id, "peer": req.peer_id, "iat": iat, "exp": exp, "jti": jti}
  echo     tok = jwt.encode^(payload, server_key, algorithm="ES256", headers={"kid": "k1"}^)
  echo     return {"token": tok, "exp_ms": TOKEN_TTL_SEC * 1000}
  echo
  echo
  echo @app.post^("/v1/rooms/{room_id}/presence/upsert"^)
  echo def presence_upsert^(room_id: str, req: PresenceUpsertReq, authorization: str = Header^(default=""^)^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     bearer = authorization.removeprefix^("Bearer " ^).strip^(^)
  echo     payload = verify_token^(bearer, room_id=room_id^)
  echo     if payload.get^("sub"^) != req.callsign or payload.get^("peer"^) != req.peer_id:
  echo         raise HTTPException^(status_code=401, detail="token_mismatch"^)
  echo     presence.setdefault^(room_id, {}^)
  echo     presence[room_id][req.peer_id] = PresenceItem^(req.callsign, req.peer_id, now_ms^(^)^)
  echo     return {"ok": True, "ttl_ms": PRESENCE_TTL_SEC * 1000}
  echo
  echo
  echo @app.get^("/v1/rooms/{room_id}/presence"^)
  echo def presence_list^(room_id: str^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     peers = []
  echo     for item in presence.get^(room_id, {}^).values^(^):
  echo         peers.append^({"callsign": item.callsign, "peer_id": item.peer_id, "last_seen_ms": item.last_seen_ms}^)
  echo     peers.sort^(key=lambda x: x["callsign"]^)
  echo     return {"room_id": room_id, "peers": peers}
  echo
  echo
  echo @app.post^("/v1/webrtc/session/create"^)
  echo def session_create^(req: SessionCreateReq, authorization: str = Header^(default=""^)^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     bearer = authorization.removeprefix^("Bearer " ^).strip^(^)
  echo     payload = verify_token^(bearer, room_id=req.room_id^)
  echo     if payload.get^("peer"^) != req.from_peer_id:
  echo         raise HTTPException^(status_code=401, detail="token_mismatch"^)
  echo     session_id = str^(uuid.uuid4^(^)^)
  echo     expires_ms = now_ms^(^) + SIGNAL_TTL_SEC * 1000
  echo     sess = Session^(session_id, req.room_id, req.from_peer_id, req.to_peer_id, expires_ms, {req.from_peer_id: [], req.to_peer_id: []}^)
  echo     sessions[session_id] = sess
  echo     inbox.setdefault^(req.to_peer_id, []^).append^(session_id^)
  echo     return {"session_id": session_id, "ttl_ms": SIGNAL_TTL_SEC * 1000}
  echo
  echo
  echo @app.get^("/v1/webrtc/inbox"^)
  echo def webrtc_inbox^(peer_id: str^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     return {"peer_id": peer_id, "sessions": inbox.get^(peer_id, []^)}
  echo
  echo
  echo def push_event^(session_id: str, from_peer_id: str, ev: Dict[str, Any]^) -^> None:
  echo     sess = sessions.get^(session_id^)
  echo     if not sess:
  echo         raise HTTPException^(status_code=404, detail="session_not_found"^)
  echo     if from_peer_id not in sess.queues:
  echo         raise HTTPException^(status_code=403, detail="not_in_session"^)
  echo     other = sess.to_peer_id if from_peer_id == sess.from_peer_id else sess.from_peer_id
  echo     sess.queues[other].append^(ev^)
  echo
  echo
  echo @app.post^("/v1/webrtc/session/{session_id}/offer"^)
  echo def webrtc_offer^(session_id: str, req: SDPPostReq, authorization: str = Header^(default=""^)^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     bearer = authorization.removeprefix^("Bearer " ^).strip^(^)
  echo     payload = verify_token^(bearer^)
  echo     if payload.get^("peer"^) != req.from_peer_id:
  echo         raise HTTPException^(status_code=401, detail="token_mismatch"^)
  echo     push_event^(session_id, req.from_peer_id, {"type": "offer", "sdp": req.sdp}^)
  echo     return {"ok": True}
  echo
  echo
  echo @app.post^("/v1/webrtc/session/{session_id}/answer"^)
  echo def webrtc_answer^(session_id: str, req: SDPPostReq, authorization: str = Header^(default=""^)^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     bearer = authorization.removeprefix^("Bearer " ^).strip^(^)
  echo     payload = verify_token^(bearer^)
  echo     if payload.get^("peer"^) != req.from_peer_id:
  echo         raise HTTPException^(status_code=401, detail="token_mismatch"^)
  echo     push_event^(session_id, req.from_peer_id, {"type": "answer", "sdp": req.sdp}^)
  echo     return {"ok": True}
  echo
  echo
  echo @app.post^("/v1/webrtc/session/{session_id}/ice"^)
  echo def webrtc_ice^(session_id: str, req: ICEPostReq, authorization: str = Header^(default=""^)^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     bearer = authorization.removeprefix^("Bearer " ^).strip^(^)
  echo     payload = verify_token^(bearer^)
  echo     if payload.get^("peer"^) != req.from_peer_id:
  echo         raise HTTPException^(status_code=401, detail="token_mismatch"^)
  echo     push_event^(session_id, req.from_peer_id, {"type": "ice", "candidate": req.candidate, "sdpMid": req.sdpMid, "sdpMLineIndex": req.sdpMLineIndex}^)
  echo     return {"ok": True}
  echo
  echo
  echo @app.get^("/v1/webrtc/session/{session_id}/poll"^)
  echo def webrtc_poll^(session_id: str, peer_id: str, cursor: int = 0, authorization: str = Header^(default=""^)^) -^> Dict[str, Any]:
  echo     cleanup^(^)
  echo     bearer = authorization.removeprefix^("Bearer " ^).strip^(^)
  echo     payload = verify_token^(bearer^)
  echo     if payload.get^("peer"^) != peer_id:
  echo         raise HTTPException^(status_code=401, detail="token_mismatch"^)
  echo     sess = sessions.get^(session_id^)
  echo     if not sess or peer_id not in sess.queues:
  echo         raise HTTPException^(status_code=404, detail="session_not_found"^)
  echo     q = sess.queues[peer_id]
  echo     if cursor ^< 0 or cursor ^> len^(q^):
  echo         cursor = 0
  echo     events = q[cursor:]
  echo     return {"events": events, "next_cursor": len^(q^)}
  echo
  echo
  echo if __name__ == "__main__":
  echo     import uvicorn
  echo     uvicorn.run^(app, host="127.0.0.1", port=8080^)
) > central_server.py

echo [3/3] Writing peer_client.html
(
  echo ^<!doctype html^>
  echo ^<html lang="ja"^>
  echo ^<head^>
  echo   ^<meta charset="utf-8"/^>
  echo   ^<title^>WorldMorse Peer (Prototype)^</title^>
  echo ^</head^>
  echo ^<body^>
  echo ^<h2^>WorldMorse Prototype^</h2^>
  echo ^<p^>Open this page in two tabs. Use different callsigns.^</p^>
  echo ^<div^>
  echo Central: ^<input id="central" value="http://127.0.0.1:8080"^> 
  echo Room: ^<input id="room" value="wm-hf-7000-7200"^> 
  echo Callsign: ^<input id="callsign" value="JA1AAA"^>
  echo ^</div^>
  echo ^<div^>
  echo ^<button id="genKey"^>鍵生成^</button^>
  echo ^<button id="register"^>登録^</button^>
  echo ^<button id="issue"^>トークン発行^</button^>
  echo ^<button id="start"^>起動^</button^>
  echo ^</div^>
  echo ^<pre id="log" style="white-space:pre-wrap;border:1px solid #ccc;padding:10px;height:360px;overflow:auto"^>^</pre^>
  echo ^<script^>
  echo const $ = (id) =^> document.getElementById(id);
  echo const log = (s) =^> { const el = $("log"); el.textContent += s + "\n"; el.scrollTop = el.scrollHeight; };
  echo function b64url(buf){
  echo   const b = new Uint8Array(buf); let s=""; for(const x of b) s += String.fromCharCode(x);
  echo   return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
  echo }
  echo function utf8(s){ return new TextEncoder().encode(s); }
  echo let privKey=null, pubJwk=null, token=null;
  echo const peerId = crypto.randomUUID();
  echo async function api(path, opts={}){
  echo   const base = $("central").value.trim();
  echo   const url = base + path;
  echo   const headers = opts.headers || {};
  echo   if(token) headers["Authorization"] = "Bearer " + token;
  echo   headers["Content-Type"] = "application/json";
  echo   const res = await fetch(url, {...opts, headers});
  echo   const text = await res.text();
  echo   if(!res.ok){ log("HTTP "+res.status+" "+url+" => "+text); throw new Error(text); }
  echo   return JSON.parse(text);
  echo }
  echo async function genKey(){
  echo   const kp = await crypto.subtle.generateKey({name:"ECDSA", namedCurve:"P-256"}, true, ["sign","verify"]);
  echo   privKey = kp.privateKey;
  echo   pubJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  echo   log("Key generated. peer_id="+peerId);
  echo }
  echo async function signRaw(msgBytes){
  echo   const derBuf = await crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, privKey, msgBytes);
  echo   const der = new Uint8Array(derBuf);
  echo   function readLen(a,i){ let len=a[i++]; if(len & 0x80){ const n=len & 0x7f; if(n==0||n^>4) throw new Error("bad der"); len=0; for(let k=0;k^<n;k++) len=(len^<^<8)|a[i++]; } return [len,i]; }
  echo   let i=0; if(der[i++]!==0x30) throw new Error("bad der"); let L; [L,i]=readLen(der,i);
  echo   if(der[i++]!==0x02) throw new Error("bad der"); let rL; [rL,i]=readLen(der,i); let r=der.slice(i,i+rL); i+=rL;
  echo   if(der[i++]!==0x02) throw new Error("bad der"); let sL; [sL,i]=readLen(der,i); let s=der.slice(i,i+sL); i+=sL;
  echo   const to32 = (arr)=^>{ while(arr.length^>0 && arr[0]===0x00) arr=arr.slice(1); if(arr.length^>32) arr=arr.slice(arr.length-32);
  echo     if(arr.length^<32){ const out=new Uint8Array(32); out.set(arr,32-arr.length); return out; } return new Uint8Array(arr); };
  echo   const r32=to32(r), s32=to32(s); const raw=new Uint8Array(64); raw.set(r32,0); raw.set(s32,32); return b64url(raw.buffer);
  echo }
  echo async function register(){
  echo   const callsign = $("callsign").value.trim().toUpperCase();
  echo   const nonce = crypto.randomUUID();
  echo   const msg = `register|${callsign}|${nonce}`;
  echo   const sig = await signRaw(utf8(msg));
  echo   await api("/v1/registry/register",{method:"POST", body: JSON.stringify({callsign, public_key_jwk: pubJwk, nonce, signature_b64u: sig})});
  echo   log("Registered callsign="+callsign);
  echo }
  echo async function issue(){
  echo   const callsign = $("callsign").value.trim().toUpperCase();
  echo   const room_id = $("room").value.trim();
  echo   const nonce = crypto.randomUUID();
  echo   const msg = `issue|${callsign}|${room_id}|${peerId}|${nonce}`;
  echo   const sig = await signRaw(utf8(msg));
  echo   const r = await api("/v1/token/issue",{method:"POST", body: JSON.stringify({callsign, room_id, peer_id: peerId, nonce, signature_b64u: sig})});
  echo   token = r.token;
  echo   log("Token issued. head="+token.slice(0,20)+"...");
  echo }
  echo async function start(){
  echo   if(!token || token.length^<20){ log("ERR token missing. click トークン発行 first."); return; }
  echo   const room_id = $("room").value.trim();
  echo   const callsign = $("callsign").value.trim().toUpperCase();
  echo   await api(`/v1/rooms/${encodeURIComponent(room_id)}/presence/upsert`,{method:"POST", body: JSON.stringify({peer_id: peerId, callsign})});
  echo   log("Presence upsert OK");
  echo }
  echo $("genKey").onclick = ()=^> genKey().catch(e=^>log("ERR "+e));
  echo $("register").onclick = ()=^> register().catch(e=^>log("ERR "+e));
  echo $("issue").onclick = ()=^> issue().catch(e=^>log("ERR "+e));
  echo $("start").onclick = ()=^> start().catch(e=^>log("ERR "+e));
  echo log("Ready: 鍵生成 → 登録 → トークン発行 → 起動");
  echo ^</script^>
  echo ^</body^>
  echo ^</html^>
) > peer_client.html

echo Done.
echo Now run: python central_server.py
echo Then open: http://127.0.0.1:8080/static/peer_client.html
pause
endlocal
