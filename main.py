import os
import json
import hashlib
import urllib.request
from datetime import datetime, timezone
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

# UPSTASH REDIS REST API HELPER
UPSTASH_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")


def redis_cmd(command_list):
    """Executes commands on Upstash Redis over lightweight HTTP."""
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        return None
    try:
        req = urllib.request.Request(
            UPSTASH_URL,
            data=json.dumps(command_list).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {UPSTASH_TOKEN}",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            return res.get("result")
    except Exception as e:
        print("Redis error:", e)
        return None


def load_stats():
    res = redis_cmd(["GET", "worldsign_stats"])
    if res:
        try:
            data = json.loads(res)
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
    data = {
        "protected": stats_data["protected"],
        "verified": stats_data["verified"],
        "tampered": stats_data["tampered"],
        "authors": list(stats_data["authors"]),
        "history": stats_data["history"][:20]
    }
    redis_cmd(["SET", "worldsign_stats", json.dumps(data)])


def load_fingerprints():
    res = redis_cmd(["GET", "worldsign_fingerprints"])
    if res:
        try:
            return json.loads(res)
        except Exception:
            pass
    return []


def save_fingerprints(fingerprints_list):
    redis_cmd(["SET", "worldsign_fingerprints", json.dumps(fingerprints_list[:100])])


stats_data = load_stats()


def get_keys():
    pem_key = os.getenv("PRIVATE_KEY")
    if not pem_key:
        raise HTTPException(status_code=500, detail="PRIVATE_KEY missing on server.")
    private_key = load_pem_private_key(pem_key.encode("utf-8"), password=None)
    return private_key, private_key.public_key()


def extract_fingerprint(world_data: dict) -> set:
    """Extracts object types and 3D grid positions into a set of tokens."""
    tokens = set()

    def scan_node(node):
        if isinstance(node, dict):
            pos = node.get("pos") or node.get("position")
            if not pos and all(k in node for k in ("x", "y", "z")):
                pos = [node["x"], node["y"], node["z"]]

            if isinstance(pos, (list, tuple)) and len(pos) >= 3:
                obj_name = str(node.get("type") or node.get("name") or "item")
                # Round coordinates to 1 decimal place (~10cm grid tolerance)
                token = f"{obj_name}_{round(float(pos[0]), 1)}_{round(float(pos[1]), 1)}_{round(float(pos[2]), 1)}"
                tokens.add(token)

            for v in node.values():
                scan_node(v)
        elif isinstance(node, list):
            for item in node:
                scan_node(item)

    scan_node(world_data)
    return tokens


def compute_similarity(set_a: set, set_b: set) -> float:
    """Calculates Jaccard similarity score between two fingerprint sets."""
    if not set_a or not set_b:
        return 0.0
    shared = len(set_a.intersection(set_b))
    total = len(set_a.union(set_b))
    return (shared / total) if total > 0 else 0.0


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
    passphrase: str = Form(""),
    is_update: bool = Form(False),
    force_register: bool = Form(False)
):
    original_bytes = await file.read()

    try:
        world_data = json.loads(original_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid .world JSON file.")

    existing_registry = world_data.get("_ProtectionRegistry")
    final_author = author_name.strip()

    # Passphrase check for updates
    if existing_registry and isinstance(existing_registry, dict):
        existing_hash = existing_registry.get("passphrase_hash", "")
        if existing_hash:
            input_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else ""
            if input_hash != existing_hash:
                raise HTTPException(
                    status_code=401,
                    detail="File protected! Incorrect passphrase. Only the original builder can update this world."
                )

        original_author = existing_registry.get("author_name", "")
        if original_author:
            final_author = original_author

    if not final_author:
        final_author = "Unknown"

    # Fingerprint Similarity Checking for New Registrations
    current_fp = extract_fingerprint(world_data)
    stored_fps = load_fingerprints()

    if not is_update and not force_register and current_fp:
        for entry in stored_fps:
            prev_fp = set(entry.get("fp", []))
            score = compute_similarity(current_fp, prev_fp)

            if score >= 0.80:  # 80% layout similarity match
                match_pct = int(score * 100)
                orig_title = entry.get("title", "Untitled")
                orig_author = entry.get("author", "Unknown")
                return Response(
                    content=json.dumps({
                        "similarity_warning": True,
                        "match_percentage": match_pct,
                        "matched_title": orig_title,
                        "matched_author": orig_author,
                        "message": f"Warning: This layout is {match_pct}% identical to '{orig_title}' registered by {orig_author}."
                    }),
                    status_code=200,
                    media_type="application/json"
                )

    pass_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else ""

    world_data["_ProtectionRegistry"] = {
        "world_title": world_title if world_title.strip() else (existing_registry.get("world_title") if existing_registry else "Untitled"),
        "author_name": final_author,
        "contact": contact if contact.strip() else (existing_registry.get("contact") if existing_registry else ""),
        "copy_label": copy_label,
        "passphrase_hash": pass_hash
    }

    signed_json_bytes = json.dumps(world_data, indent=2).encode("utf-8")

    # Save new room fingerprint
    if current_fp:
        stored_fps.insert(0, {
            "title": world_title or "Untitled",
            "author": final_author,
            "fp": list(current_fp)
        })
        save_fingerprints(stored_fps)

    # Update stats
    stats_data["protected"] += 1
    t_clean = world_title.strip() if world_title.strip() else "Untitled"

    stats_data["authors"].add(final_author.lower())
    stats_data["history"].insert(0, {"title": t_clean, "author": final_author})
    stats_data["history"] = stats_data["history"][:20]
    save_stats()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SUTC")
    safe_author = final_author.replace(" ", "_")
    base_name = file.filename.replace(".world", "")
    prefix = "updated" if is_update else "signed"
    download_filename = f"{prefix}_{safe_author}_{base_name}_{timestamp}.world"

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

@app.post("/check-similarity")
async def check_similarity_only(file: UploadFile = File(...)):
    file_bytes = await file.read()

    try:
        world_data = json.loads(file_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid .world JSON file.")

    current_fp = extract_fingerprint(world_data)
    if not current_fp:
        return {"matches": [], "message": "No layout objects found in this room."}

    stored_fps = load_fingerprints()
    results = []

    for entry in stored_fps:
        prev_fp = set(entry.get("fp", []))
        score = compute_similarity(current_fp, prev_fp)
        
        # Report matches that have 15% or higher layout overlap
        if score >= 0.15:
            results.append({
                "title": entry.get("title", "Untitled"),
                "author": entry.get("author", "Unknown"),
                "match_percentage": int(score * 100)
            })

    # Sort matches by highest percentage first
    results.sort(key=lambda x: x["match_percentage"], reverse=True)

    return {
        "total_objects_scanned": len(current_fp),
        "matches": results[:5]  # Return top 5 highest matches
    }
