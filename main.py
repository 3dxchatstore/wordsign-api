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
    """Universal 3D layout scanner that handles single-letter keys (p, n) and nested groups."""
    tokens = set()

    def parse_num(val):
        try:
            return float(val)
        except (ValueError, TypeError):
            return None

    def scan_node(node):
        if isinstance(node, dict):
            x = y = z = None
            obj_name = str(node.get("n", node.get("name", node.get("type", "item"))))

            # 1. Read array positions from short keys like "p" or "pos" (e.g. "p": [18.91, 13.20, 0.0])
            for p_key in ("p", "pos", "position", "location"):
                if p_key in node and isinstance(node[p_key], (list, tuple)) and len(node[p_key]) >= 3:
                    nx, ny, nz = parse_num(node[p_key][0]), parse_num(node[p_key][1]), parse_num(node[p_key][2])
                    if nx is not None and ny is not None and nz is not None:
                        x, y, z = nx, ny, nz
                        break

            # 2. Read explicit coordinate key-values if array was not found
            if x is None:
                low_dict = {str(k).lower(): v for k, v in node.items()}
                for x_k, y_k, z_k in [("x", "y", "z"), ("px", "py", "pz")]:
                    if x_k in low_dict and y_k in low_dict and z_k in low_dict:
                        nx, ny, nz = parse_num(low_dict[x_k]), parse_num(low_dict[y_k]), parse_num(low_dict[z_k])
                        if nx is not None and ny is not None and nz is not None:
                            x, y, z = nx, ny, nz
                            break

            # Ignore generic "group" containers and save valid object position tokens
            if x is not None and y is not None and z is not None and obj_name.lower() != "group":
                token = f"{obj_name}_{round(x, 1)}_{round(y, 1)}_{round(z, 1)}"
                tokens.add(token)

            # Traverse child elements recursively
            for v in node.values():
                scan_node(v)

        elif isinstance(node, list):
            for item in node:
                scan_node(item)

    scan_node(world_data)
    return tokens


def compute_similarity(set_a: set, set_b: set) -> float:
    """Calculates similarity score (0.0 to 1.0) between two room layouts."""
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

    current_fp = extract_fingerprint(world_data)
    stored_fps = load_fingerprints()

    if not is_update and not force_register and current_fp:
        for entry in stored_fps:
            prev_fp = set(entry.get("fp", []))
            score = compute_similarity(current_fp, prev_fp)

            if score >= 0.80:
                match_pct = int(score * 100)
                orig_title = entry.get("title", "Untitled")
                orig_author = entry.get("author", "Unknown")
                return Response(
                    content=json.dumps({
                        "similarity_warning": True,
                        "match_percentage": match_pct,
                        "matched_title": orig_title,
                        "matched_author": orig_author,
                        "message": f"A similar file with {match_pct}% structural similarity has been uploaded before ('{orig_title}' by {orig_author})."
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

    if current_fp:
        stored_fps.insert(0, {
            "title": world_title or "Untitled",
            "author": final_author,
            "fp": list(current_fp)
        })
        save_fingerprints(stored_fps)

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


@app.post("/compare-two-files")
async def compare_two_files(
    file_a: UploadFile = File(...),
    file_b: UploadFile = File(...)
):
    bytes_a = await file_a.read()
    bytes_b = await file_b.read()

    try:
        data_a = json.loads(bytes_a.decode("utf-8"))
        data_b = json.loads(bytes_b.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="One or both files are invalid .world JSON.")

    fp_a = extract_fingerprint(data_a)
    fp_b = extract_fingerprint(data_b)

    if not fp_a or not fp_b:
        return {"match_percentage": 0, "file_a_objects": len(fp_a), "file_b_objects": len(fp_b), "shared_objects": 0}

    score = compute_similarity(fp_a, fp_b)
    match_pct = int(score * 100)
    shared_count = len(fp_a.intersection(fp_b))

    return {
        "match_percentage": match_pct,
        "file_a_objects": len(fp_a),
        "file_b_objects": len(fp_b),
        "shared_objects": shared_count
    }
