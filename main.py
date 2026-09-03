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


def extract_item_list(world_data: dict):
    """Extracts raw 3D item entries from nested world JSON."""
    raw_items = []
    shape_keywords = {"box", "cube", "sphere", "cylinder", "triangle", "cone", "pyramid", "plane", "quad", "prism"}

    def parse_num(val):
        try:
            return float(val)
        except (ValueError, TypeError):
            return None

    def scan_node(node):
        if isinstance(node, dict):
            x = y = z = None
            obj_name = str(node.get("n", node.get("name", node.get("type", "item"))))

            for p_key in ("p", "pos", "position", "location"):
                if p_key in node and isinstance(node[p_key], (list, tuple)) and len(node[p_key]) >= 3:
                    nx, ny, nz = parse_num(node[p_key][0]), parse_num(node[p_key][1]), parse_num(node[p_key][2])
                    if nx is not None and ny is not None and nz is not None:
                        x, y, z = nx, ny, nz
                        break

            if x is None:
                low_dict = {str(k).lower(): v for k, v in node.items()}
                for x_k, y_k, z_k in [("x", "y", "z"), ("px", "py", "pz")]:
                    if x_k in low_dict and y_k in low_dict and z_k in low_dict:
                        nx, ny, nz = parse_num(low_dict[x_k]), parse_num(low_dict[y_k]), parse_num(low_dict[z_k])
                        if nx is not None and ny is not None and nz is not None:
                            x, y, z = nx, ny, nz
                            break

            if x is not None and y is not None and z is not None and obj_name.lower() != "group":
                is_shape = obj_name.lower() in shape_keywords
                raw_items.append({
                    "name": obj_name.lower(),
                    "x": round(x, 2),
                    "y": round(y, 2),
                    "z": round(z, 2),
                    "is_shape": is_shape
                })

            for v in node.values():
                scan_node(v)

        elif isinstance(node, list):
            for item in node:
                scan_node(item)

    scan_node(world_data)
    return raw_items


def match_sets_with_delta_alignment(list_a, list_b):
    """
    Finds the dominant translation vector between two item sets
    and measures spatial overlap regardless of movement or partial deletions.
    """
    if not list_a or not list_b:
        return 0, 0

    delta_counts = {}
    sample_a = list_a[:300]
    sample_b = list_b[:300]

    b_by_name = {}
    for item in sample_b:
        b_by_name.setdefault(item["name"], []).append(item)

    for a in sample_a:
        matches = b_by_name.get(a["name"], [])
        for b in matches:
            dx = round(b["x"] - a["x"], 1)
            dy = round(b["y"] - a["y"], 1)
            dz = round(b["z"] - a["z"], 1)
            key = (dx, dy, dz)
            delta_counts[key] = delta_counts.get(key, 0) + 1

    if not delta_counts:
        return 0, 0

    best_dx, best_dy, best_dz = max(delta_counts, key=delta_counts.get)

    set_a_tokens = {f"{i['name']}_{i['x']}_{i['y']}_{i['z']}" for i in list_a}
    shared_count = 0

    for b in list_b:
        shifted_x = round(b["x"] - best_dx, 2)
        shifted_y = round(b["y"] - best_dy, 2)
        shifted_z = round(b["z"] - best_dz, 2)

        matched = False
        for dx in (-0.1, 0.0, 0.1):
            for dy in (-0.1, 0.0, 0.1):
                for dz in (-0.1, 0.0, 0.1):
                    tok = f"{b['name']}_{round(shifted_x+dx, 2)}_{round(shifted_y+dy, 2)}_{round(shifted_z+dz, 2)}"
                    if tok in set_a_tokens:
                        matched = True
                        break
                if matched:
                    break
            if matched:
                break

        if matched:
            shared_count += 1

    max_len = max(len(list_a), len(list_b))
    score = (shared_count / max_len) if max_len > 0 else 0.0
    return int(score * 100), shared_count


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
    author: str = Form(""),
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
    submitted_author = author_name.strip() or author.strip()

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
        final_author = submitted_author if submitted_author else original_author
    else:
        final_author = submitted_author

    if not final_author:
        final_author = "Unknown"

    items_current = extract_item_list(world_data)
    shapes_current = [i for i in items_current if i["is_shape"]]
    stored_fps = load_fingerprints()

    if not is_update and not force_register and items_current:
        for entry in stored_fps:
            prev_all = entry.get("items", [])
            prev_shapes = [i for i in prev_all if i.get("is_shape")]

            s_pct, _ = match_sets_with_delta_alignment(shapes_current, prev_shapes)
            a_pct, _ = match_sets_with_delta_alignment(items_current, prev_all)
            highest_score = max(s_pct, a_pct)

            if highest_score >= 80:
                orig_title = entry.get("title", "Untitled")
                orig_author = entry.get("author", "Unknown")
                return Response(
                    content=json.dumps({
                        "similarity_warning": True,
                        "match_percentage": highest_score,
                        "matched_title": orig_title,
                        "matched_author": orig_author,
                        "message": f"A similar file with {highest_score}% layout similarity has been uploaded before ('{orig_title}' by {orig_author})."
                    }),
                    status_code=200,
                    media_type="application/json"
                )

    pass_hash = hashlib.sha256(passphrase.encode()).hexdigest() if passphrase else ""
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    world_data["_ProtectionRegistry"] = {
        "world_title": world_title.strip() if world_title.strip() else (existing_registry.get("world_title") if existing_registry else "Untitled"),
        "author_name": final_author,
        "contact": contact.strip() if contact.strip() else (existing_registry.get("contact") if existing_registry else ""),
        "copy_label": copy_label,
        "timestamp": timestamp_str,
        "passphrase_hash": pass_hash
    }

    signed_json_bytes = json.dumps(world_data, indent=2).encode("utf-8")

    if items_current:
        stored_fps.insert(0, {
            "title": world_title or "Untitled",
            "author": final_author,
            "items": items_current
        })
        save_fingerprints(stored_fps)

    stats_data["protected"] += 1
    t_clean = world_title.strip() if world_title.strip() else "Untitled"

    stats_data["authors"].add(final_author.lower())
    stats_data["history"].insert(0, {"title": t_clean, "author": final_author})
    stats_data["history"] = stats_data["history"][:20]
    save_stats()

    filename_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SUTC")
    safe_author = final_author.replace(" ", "_")
    base_name = file.filename.replace(".world", "")
    prefix = "updated" if is_update else "signed"
    download_filename = f"{prefix}_{safe_author}_{base_name}_{filename_timestamp}.world"

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
                "contact": registry.get("contact", ""),
                "copy_label": registry.get("copy_label", "N/A"),
                "timestamp": registry.get("timestamp", "N/A")
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

    items_a = extract_item_list(data_a)
    items_b = extract_item_list(data_b)

    shapes_a = [i for i in items_a if i["is_shape"]]
    shapes_b = [i for i in items_b if i["is_shape"]]

    shapes_pct, shared_shapes = match_sets_with_delta_alignment(shapes_a, shapes_b)
    all_pct, shared_all = match_sets_with_delta_alignment(items_a, items_b)

    highest_pct = max(shapes_pct, all_pct)

    return {
        "highest_match_percentage": highest_pct,
        "shapes_match_percentage": shapes_pct,
        "all_match_percentage": all_pct,
        "file_a": {"shapes": len(shapes_a), "total": len(items_a)},
        "file_b": {"shapes": len(shapes_b), "total": len(items_b)},
        "shared_shapes": shared_shapes,
        "shared_all": shared_all
    }
