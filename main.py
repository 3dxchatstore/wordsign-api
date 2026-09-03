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


def extract_fingerprints(world_data: dict):
    """
    Extracts two-layer 3D fingerprints:
    1. Shape-Only FP (Basic architecture blocks)
    2. Full Map FP (All items including furniture)
    Applies Bounding-Box Centering and Scale Normalization.
    """
    raw_items = []

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
                raw_items.append({"name": obj_name, "x": x, "y": y, "z": z})

            for v in node.values():
                scan_node(v)

        elif isinstance(node, list):
            for item in node:
                scan_node(item)

    scan_node(world_data)

    if not raw_items:
        return set(), set(), 0, 0

    # Calculate bounding box for center calculation
    xs = [i["x"] for i in raw_items]
    ys = [i["y"] for i in raw_items]
    zs = [i["z"] for i in raw_items]

    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)
    min_z, max_z = min(zs), max(zs)

    cx = (min_x + max_x) / 2.0
    cy = (min_y + max_y) / 2.0
    cz = (min_z + max_z) / 2.0

    # Max dimension for scale normalization
    max_dim = max(max_x - min_x, max_y - min_y, max_z - min_z)
    if max_dim <= 0.0001:
        max_dim = 1.0

    shapes_fp = set()
    all_fp = set()

    shape_keywords = {"box", "cube", "sphere", "cylinder", "triangle", "cone", "pyramid", "plane", "quad", "prism"}
    shapes_count = 0

    for item in raw_items:
        # Centered and normalized coordinates (rounded to 2 decimal places)
        rx = round((item["x"] - cx) / max_dim, 2)
        ry = round((item["y"] - cy) / max_dim, 2)
        rz = round((item["z"] - cz) / max_dim, 2)

        token = f"{item['name'].lower()}_{rx}_{ry}_{rz}"
        all_fp.add(token)

        if item["name"].lower() in shape_keywords:
            shapes_fp.add(token)
            shapes_count += 1

    return shapes_fp, all_fp, shapes_count, len(raw_items)


def compute_similarity(set_a: set, set_b: set) -> float:
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

    shapes_fp, all_fp, shapes_cnt, total_cnt = extract_fingerprints(world_data)
    stored_fps = load_fingerprints()

    # Two-layer background database scan
    if not is_update and not force_register and (shapes_fp or all_fp):
        for entry in stored_fps:
            prev_shapes = set(entry.get("shapes_fp", []))
            prev_all = set(entry.get("all_fp", entry.get("fp", [])))

            score_shapes = compute_similarity(shapes_fp, prev_shapes)
            score_all = compute_similarity(all_fp, prev_all)
            highest_score = max(score_shapes, score_all)

            if highest_score >= 0.80:
                match_pct = int(highest_score * 100)
                orig_title = entry.get("title", "Untitled")
                orig_author = entry.get("author", "Unknown")
                return Response(
                    content=json.dumps({
                        "similarity_warning": True,
                        "match_percentage": match_pct,
                        "matched_title": orig_title,
                        "matched_author": orig_author,
                        "message": f"A similar file with {match_pct}% layout similarity has been uploaded before ('{orig_title}' by {orig_author})."
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

    if all_fp:
        stored_fps.insert(0, {
            "title": world_title or "Untitled",
            "author": final_author,
            "shapes_fp": list(shapes_fp),
            "all_fp": list(all_fp)
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

    shapes_a, all_a, shapes_cnt_a, total_cnt_a = extract_fingerprints(data_a)
    shapes_b, all_b, shapes_cnt_b, total_cnt_b = extract_fingerprints(data_b)

    score_shapes = compute_similarity(shapes_a, shapes_b)
    score_all = compute_similarity(all_a, all_b)

    shapes_pct = int(score_shapes * 100)
    all_pct = int(score_all * 100)
    highest_pct = max(shapes_pct, all_pct)

    return {
        "highest_match_percentage": highest_pct,
        "shapes_match_percentage": shapes_pct,
        "all_match_percentage": all_pct,
        "file_a": {"shapes": shapes_cnt_a, "total": total_cnt_a},
        "file_b": {"shapes": shapes_cnt_b, "total": total_cnt_b},
        "shared_shapes": len(shapes_a.intersection(shapes_b)),
        "shared_all": len(all_a.intersection(all_b))
    }
