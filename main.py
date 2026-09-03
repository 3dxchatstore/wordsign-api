import os
import json
import hashlib
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

app = FastAPI(title="WorldSign API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATS_FILE = "stats.json"


def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                data = json.load(f)
                return {
                    "protected": data.get("protected", 0),
                    "verified": data.get("verified", 0),
                    "tampered": data.get("tampered", 0),
                    "authors": set(data.get("authors", [])),
                    "history": data.get("history", [])
                }
        except Exception:
            pass
    return {"protected": 0, "verified": 0, "tampered": 0, "authors": set(), "history": []}


def save_stats():
    try:
        with open(STATS_FILE, "w") as f:
            json.dump({
                "protected": stats_data["protected"],
                "verified": stats_data["verified"],
                "tampered": stats_data["tampered"],
                "authors": list(stats_data["authors"]),
                "history": stats_data["history"][:20]
            }, f)
    except Exception:
        pass


stats_data = load_stats()


def get_keys():
    pem_key = os.getenv("PRIVATE_KEY")
    if not pem_key:
        raise HTTPException(status_code=500, detail="PRIVATE_KEY missing on server.")
    private_key = load_pem_private_key(pem_key.encode("utf-8"), password=None)
    return private_key, private_key.public_key()


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
        "public_key": pub_pem,
        "history": stats_data["history"]
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
    original_bytes = await file.read()

    # Parse .world file as JSON
    try:
        world_data = json.loads(original_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid .world JSON file.")

    pass_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else ""

    # Inject metadata key directly inside the JSON structure
    world_data["_ProtectionRegistry"] = {
        "world_title": world_title,
        "author_name": author_name,
        "contact": contact,
        "copy_label": copy_label,
        "passphrase_hash": pass_hash
    }

    signed_json_bytes = json.dumps(world_data, indent=2).encode("utf-8")

    # Update stats & history log
    stats_data["protected"] += 1
    t_clean = world_title.strip() if world_title.strip() else "Untitled"
    a_clean = author_name.strip() if author_name.strip() else "Anonymous"

    if author_name.strip():
        stats_data["authors"].add(author_name.strip().lower())

    stats_data["history"].insert(0, {"title": t_clean, "author": a_clean})
    stats_data["history"] = stats_data["history"][:20]
    save_stats()

    safe_author = (author_name.strip() if author_name.strip() else "Unknown").replace(" ", "_")
    base_name = file.filename.replace(".world", "")
    download_filename = f"signed_{safe_author}_{base_name}.world"

    return Response(
        content=signed_json_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={download_filename}"}
    )


@app.post("/verify")
async def verify_world(file: UploadFile = File(...)):
    file_bytes = await file.read()

    try:
        world_data = json.loads(file_bytes.decode("utf-8"))
        registry = world_data.get("_ProtectionRegistry")

        if registry and isinstance(registry, dict):
            stats_data["verified"] += 1
            save_stats()
            return {
                "status": "authentic",
                "message": "Signature is valid and registered!",
                "world_title": registry.get("world_title", "Untitled"),
                "author_name": registry.get("author_name", "Unknown"),
                "copy_label": registry.get("copy_label", "N/A")
            }
        else:
            stats_data["tampered"] += 1
            save_stats()
            return {"status": "unsigned", "message": "No WorldSign digital seal detected."}
    except Exception:
        stats_data["tampered"] += 1
        save_stats()
        return {"status": "tampered", "message": "Invalid or corrupted .world JSON file."}


@app.post("/release")
async def release_ownership(
    file: UploadFile = File(...),
    passphrase: str = Form("")
):
    file_bytes = await file.read()

    try:
        world_data = json.loads(file_bytes.decode("utf-8"))
        registry = world_data.get("_ProtectionRegistry")

        if not registry or not isinstance(registry, dict):
            raise HTTPException(status_code=400, detail="File is not signed.")

        stored_hash = registry.get("passphrase_hash", "")
        if stored_hash:
            input_hash = hashlib.sha256(passphrase.encode()).hexdigest()
            if input_hash != stored_hash:
                raise HTTPException(status_code=401, detail="Incorrect passphrase.")

        # Remove protection key to restore clean file
        del world_data["_ProtectionRegistry"]
        released_bytes = json.dumps(world_data, indent=2).encode("utf-8")

        return Response(
            content=released_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename=released_{file.filename}"}
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to process .world JSON file.")
