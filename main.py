"""Anthropic Proxy — standalone, separate from UUMit LLM proxy."""
import os, json, base64, hashlib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import httpx

app = FastAPI(title="Anthropic Proxy")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

# ─── Models ────────────────────────────────────────────

class EncryptRequest(BaseModel):
    key: str
    password: str
    method: str = "aes-256-cbc"

class ProxyRequest(BaseModel):
    encrypted_key: str
    password: str
    iv: str
    salt: str
    method: str = "aes-256-cbc"
    messages: list
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 1024
    system: str = ""

# ─── Crypto ────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

def encrypt_aes(key_str: str, password: str, method: str) -> dict:
    salt = get_random_bytes(16)
    aes_key = _derive_key(password, salt)
    iv = get_random_bytes(12 if method == "aes-256-gcm" else 16)
    if method == "aes-256-gcm":
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ct, tag = cipher.encrypt_and_digest(key_str.encode())
        encrypted = ct + tag
    else:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        encrypted = cipher.encrypt(pad(key_str.encode(), AES.block_size))
    return {
        "encrypted_key": base64.b64encode(encrypted).decode(),
        "iv": base64.b64encode(iv).decode(),
        "salt": base64.b64encode(salt).decode(),
        "method": method,
    }

def decrypt_aes(encrypted_key: str, password: str, iv: str, salt: str, method: str) -> str:
    salt_bytes = base64.b64decode(salt)
    iv_bytes = base64.b64decode(iv)
    enc_bytes = base64.b64decode(encrypted_key)
    aes_key = _derive_key(password, salt_bytes)
    if method == "aes-256-gcm":
        ct, tag = enc_bytes[:-16], enc_bytes[-16:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv_bytes)
        return cipher.decrypt_and_verify(ct, tag).decode()
    else:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv_bytes)
        return unpad(cipher.decrypt(enc_bytes), AES.block_size).decode()

# ─── Routes ────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "ok", "provider": "anthropic"}

@app.post("/encrypt")
def encrypt(req: EncryptRequest):
    return encrypt_aes(req.key, req.password, req.method)

@app.post("/proxy")
async def proxy(req: ProxyRequest):
    try:
        api_key = decrypt_aes(req.encrypted_key, req.password, req.iv, req.salt, req.method)

        body = {
            "model": req.model,
            "max_tokens": req.max_tokens,
            "messages": req.messages,
        }
        if req.system:
            body["system"] = req.system

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                ANTHROPIC_URL,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": ANTHROPIC_VERSION,
                    "Content-Type": "application/json",
                },
                json=body,
            )
            return resp.json()
    except Exception as e:
        raise HTTPException(500, f"proxy failed: {e}")
