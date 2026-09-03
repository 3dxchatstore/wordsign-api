import os
import json
import struct
import hashlib
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

app = FastAPI(title="WorldSign API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FOOTER_TAG = b"WORLDSIGN_V2"
SIGNATURE_SIZE = 256
STATS_FILE = "stats.json"

# Helper functions to save and load counters permanently to disk
def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                data = json.load(f)
                return {
                    "protected": data.get("protected", 0),
                    "verified": data.get("verified", 0),
                    "tampered": data.get("tampered", 0),
                    "authors": set(data.get("authors", []))
                }
        except Exception:
            pass
    return {"protected": 0, "verified": 0, "tampered": 0, "authors": set()}

def save_stats():
    try:
        with open(STATS_FILE, "w") as f:
            json.dump({
                "protected": stats_data["protected"],
                "verified": stats_data["verified"],
                "tampered": stats_data["tampered"],
                "authors": list(stats_data["authors"])
            }, f)
    except Exception:
        pass

# Initialize persistent memory
stats_data = load_stats()


def get_keys():
    pem_key = os.getenv("PRIVATE_KEY")
    if not pem_key:
        raise HTTPException(status_code=500, detail="PRIVATE_KEY missing on server.")
    private_key = load_pem_private_key(pem_key.encode("utf-8"), password=None)
    return private_key, private_key.public_key()


def parse_footer(file_bytes):
    tag_len = len(FOOTER_TAG)
    if len(file_bytes) <= (tag_len + SIGNATURE_SIZE + 4):
        return None, None, None
    if file_bytes[-tag_len:] != FOOTER_TAG:
        return None, None, None

    sig_start = len(file_bytes) - tag_len - SIGNATURE_SIZE
    signature = file_bytes[sig_start:-tag_len]
    meta_len_start = sig_start - 4
    meta_len = struct.unpack(">I", file_bytes[meta_len_start:sig_start])[0]
    meta_start = meta_len_start - meta_len

    if meta_start < 0:
        return None, None, None

    metadata_bytes = file_bytes[meta_start:meta_len_start]
    raw_content = file_bytes[:meta_start]

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception:
        metadata = {}

    return raw_content, metadata, signature


@app.get("/stats")
def get_stats():
    _, public_key = get_keys()
    
    pub_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    return {
        "counters": {
            "protected": stats_data["protected"],
            "verified": stats_data["verified"],
            "tampered": stats_data["tampered"],
            "authors": len(stats_data["authors"])
        },
        "public_key": pub_pem
    }


@app.post("/sign")
async def sign_world(
    file: UploadFile = File(...),
    world_title: str = Form(""),
    author_name: str = Form(""),
    contact: str = Form(""),
    copy_label: str = Form(""),
    passphrase: str = Form("")
):
    private_key, _ = get_keys()
    original_bytes = await file.read()

    pass_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else ""

    metadata = {
        "world_title": world_title,
        "author_name": author_name,
        "contact": contact,
        "copy_label": copy_label,
        "passphrase_hash": pass_hash
    }

    meta_json = json.dumps(metadata).encode("utf-8")
    meta_len = len(meta_json)

    data_to_sign = original_bytes + meta_json
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    signed_bytes = original_bytes + meta_json + struct.pack(">I", meta_len) + signature + FOOTER_TAG

    # Update memory & save file
    stats_data["protected"] += 1
    if author_name.strip():
        stats_data["authors"].add(author_name.strip().lower())
    save_stats()

    return Response(
        content=signed_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=signed_{file.filename}"}
    )


@app.post("/verify")
async def verify_world(file: UploadFile = File(...)):
    _, public_key = get_keys()
    file_bytes = await file.read()

    raw_content, metadata, signature = parse_footer(file_bytes)
    if not signature:
        stats_data["tampered"] += 1
        save_stats()
        return {"status": "unsigned", "message": "No WorldSign digital seal detected."}

    meta_json = json.dumps(metadata).encode("utf-8")
    data_to_verify = raw_content + meta_json

    try:
        public_key.verify(
            signature,
            data_to_verify,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        stats_data["verified"] += 1
        save_stats()
        return {
            "status": "authentic",
            "message": "Signature is valid and registered!",
            "world_title": metadata.get("world_title", "Untitled"),
            "author_name": metadata.get("author_name", "Unknown"),
            "copy_label": metadata.get("copy_label", "N/A")
        }
    except Exception:
        stats_data["tampered"] += 1
        save_stats()
        return {"status": "tampered", "message": "File modified! Signature check failed."}


@app.post("/release")
async def release_ownership(
    file: UploadFile = File(...),
    passphrase: str = Form("")
):
    _, public_key = get_keys()
    file_bytes = await file.read()

    raw_content, metadata, signature = parse_footer(file_bytes)
    if not signature:
        raise HTTPException(status_code=400, detail="File is not signed.")

    stored_hash = metadata.get("passphrase_hash", "")
    if stored_hash:
        input_hash = hashlib.sha256(passphrase.encode()).hexdigest()
        if input_hash != stored_hash:
            raise HTTPException(status_code=401, detail="Incorrect passphrase.")

    return Response(
        content=raw_content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=released_{file.filename}"}
    )
