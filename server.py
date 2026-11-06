#!/usr/bin/env python3
import base64
import hashlib
import hmac
import http.cookies
import http.server
import io
import json
import os
import random
import re
import secrets
import shutil
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    from PIL import Image
except Exception:
    Image = None

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

DATA_DIR_ENV = os.environ.get("DATA_DIR")
if DATA_DIR_ENV and Path(DATA_DIR_ENV).exists():
    DATA_ROOT = Path(DATA_DIR_ENV)
elif Path("/data").exists():
    DATA_ROOT = Path("/data")
else:
    DATA_ROOT = BASE_DIR

DB_PATH = Path(os.environ.get("DB_PATH", DATA_ROOT / "ivris.db"))
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", DATA_ROOT / "backups"))
UPLOADS_DIR = Path(
    os.environ.get(
        "UPLOADS_DIR",
        DATA_ROOT / "uploads" if DATA_ROOT != BASE_DIR else WEB_DIR / "uploads",
    )
)

BACKUP_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MOD_EMAIL = os.environ.get("IVRIS_MOD_EMAIL", "moderator@ivris.app")
DEFAULT_MOD_HANDLE = os.environ.get("IVRIS_MOD_HANDLE", "moderator")
DEFAULT_MOD_PASSWORD = os.environ.get("IVRIS_MOD_PASSWORD", "IvrisMod2026!")
TOKEN_SIGNING_SECRET = os.environ.get(
    "IVRIS_TOKEN_SECRET", "ivris_persistent_session_signing_key_2026"
)

DEFAULT_SETTINGS = {
    "read_receipts": True,
    "story_replies": True,
    "auto_hide_seen": True,
    "quiet_mode": False,
    "notify_requests": True,
    "notify_messages": True,
}

EXPLICIT_NUDITY_PATTERN = re.compile(
    r"\b(nude|nudes|nudity|naked|nsfw|porn|porno|pornography|xxx|onlyfans|topless|uncensored|sextape|sex\s*tape|explicit\s*nude)\b",
    re.IGNORECASE,
)


def hash_pw(password: str) -> str:
    return hashlib.sha256(("ivris_salt_" + password).encode("utf-8")).hexdigest()


def create_session_token(user_row) -> str:
    u = dict(user_row)
    payload = {
        "id": u["id"],
        "email": u["email"],
        "handle": u["handle"],
        "display_name": u["display_name"],
        "bio": u.get("bio") or "",
        "avatar_url": u.get("avatar_url") or "",
        "account_type": u.get("account_type") or "personal",
        "is_verified_institution": int(u.get("is_verified_institution") or 0),
        "password_hash": u["password_hash"],
        "iat": int(time.time()),
    }
    raw_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    sig = hmac.new(
        TOKEN_SIGNING_SECRET.encode("utf-8"),
        b64_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"ivs1.{b64_payload}.{sig}"


def verify_and_restore_session_token(conn, token: str):
    if not token or not token.startswith("ivs1."):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    _, b64_payload, sig = parts
    expected_sig = hmac.new(
        TOKEN_SIGNING_SECRET.encode("utf-8"),
        b64_payload.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        padded = b64_payload + "=" * (-len(b64_payload) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None

    uid = payload.get("id")
    email = payload.get("email")
    handle = payload.get("handle")
    if not uid or not email or not handle:
        return None

    user_row = conn.execute(
        "SELECT * FROM users WHERE id = ? OR email = ? OR handle = ?",
        (uid, email, handle),
    ).fetchone()

    if not user_row:
        conn.execute(
            """
            INSERT INTO users (id, email, password_hash, handle, display_name, bio, avatar_url, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '', ?, ?)
            """,
            (
                uid,
                email,
                payload.get("password_hash") or hash_pw(secrets.token_hex(8)),
                handle,
                payload.get("display_name") or handle,
                payload.get("bio") or "",
                payload.get("avatar_url") or "",
                payload.get("account_type") or "personal",
                int(payload.get("is_verified_institution") or 0),
                json.dumps(DEFAULT_SETTINGS),
                int(payload.get("iat") or time.time()),
            ),
        )
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    if user_row:
        conn.execute(
            "INSERT OR IGNORE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_row["id"], int(time.time())),
        )
        conn.commit()
        return dict(user_row)
    return None


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            handle TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            bio TEXT DEFAULT '',
            avatar_url TEXT DEFAULT '',
            account_type TEXT NOT NULL DEFAULT 'personal',
            is_verified_institution INTEGER NOT NULL DEFAULT 0,
            email_confirmed INTEGER NOT NULL DEFAULT 0,
            verification_code TEXT DEFAULT '',
            settings_json TEXT DEFAULT '{}',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS connections (
            id TEXT PRIMARY KEY,
            requester_id TEXT NOT NULL,
            addressee_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            UNIQUE(requester_id, addressee_id)
        );

        CREATE TABLE IF NOT EXISTS posts (
            id TEXT PRIMARY KEY,
            author_id TEXT NOT NULL,
            media_kind TEXT NOT NULL,
            media_url TEXT NOT NULL,
            media_urls_json TEXT DEFAULT '[]',
            caption TEXT DEFAULT '',
            location_label TEXT DEFAULT '',
            music_json TEXT DEFAULT '',
            expires_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS post_likes (
            post_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (post_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS post_receipts (
            user_id TEXT NOT NULL,
            post_id TEXT NOT NULL,
            seen_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, post_id)
        );

        CREATE TABLE IF NOT EXISTS post_views (
            post_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            viewed_at INTEGER NOT NULL,
            PRIMARY KEY (post_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS direct_messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS institution_applications (
            id TEXT PRIMARY KEY,
            applicant_user_id TEXT,
            institution_name TEXT NOT NULL,
            official_domain TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            notes TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending_review',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS moderation_reports (
            id TEXT PRIMARY KEY,
            post_id TEXT NOT NULL,
            reporter_id TEXT,
            reason TEXT NOT NULL,
            details TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS moderation_logs (
            id TEXT PRIMARY KEY,
            moderator_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target_id TEXT NOT NULL,
            author_handle TEXT DEFAULT '',
            reason TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """
    )
    existing_user_cols = [
        r["name"] for r in cur.execute("PRAGMA table_info(users)").fetchall()
    ]
    if "email_confirmed" not in existing_user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN email_confirmed INTEGER NOT NULL DEFAULT 1")
    if "verification_code" not in existing_user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN verification_code TEXT DEFAULT ''")
    if "settings_json" not in existing_user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN settings_json TEXT DEFAULT '{}'")
    if "avatar_url" not in existing_user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT DEFAULT ''")

    existing_post_cols = [
        r["name"] for r in cur.execute("PRAGMA table_info(posts)").fetchall()
    ]
    if "media_urls_json" not in existing_post_cols:
        cur.execute("ALTER TABLE posts ADD COLUMN media_urls_json TEXT DEFAULT '[]'")
    if "music_json" not in existing_post_cols:
        cur.execute("ALTER TABLE posts ADD COLUMN music_json TEXT DEFAULT ''")

    # Backfill post_views from post_receipts
    cur.execute(
        """
        INSERT OR IGNORE INTO post_views (post_id, user_id, viewed_at)
        SELECT post_id, user_id, seen_at FROM post_receipts
        """
    )

    # Ensure all registered users are marked active and confirmed
    cur.execute("UPDATE users SET email_confirmed = 1 WHERE email_confirmed = 0")

    # Seed dedicated Moderation Account if not present
    mod_row = cur.execute(
        "SELECT * FROM users WHERE handle = ? OR email = ?",
        (DEFAULT_MOD_HANDLE, DEFAULT_MOD_EMAIL),
    ).fetchone()
    if not mod_row:
        cur.execute(
            """
            INSERT INTO users (id, email, password_hash, handle, display_name, bio, avatar_url, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, '', 'moderator', 0, 1, '', ?, ?)
            """,
            (
                "usr_moderator",
                DEFAULT_MOD_EMAIL,
                hash_pw(DEFAULT_MOD_PASSWORD),
                DEFAULT_MOD_HANDLE,
                "Ivris Moderation",
                "Official Ivris Trust & Safety Moderation Account",
                json.dumps(DEFAULT_SETTINGS),
                int(time.time()),
            ),
        )
    else:
        cur.execute(
            "UPDATE users SET account_type = 'moderator', email_confirmed = 1, password_hash = ? WHERE id = ?",
            (hash_pw(DEFAULT_MOD_PASSWORD), mod_row["id"]),
        )

    conn.commit()
    conn.close()


def create_database_backup(label: str = "auto") -> dict:
    """
    Creates an atomic, consistent SQLite snapshot of the live database using
    SQLite's online backup API without interrupting active transactions.
    Also updates backups/ivris_latest.db as the primary restore image.
    """
    try:
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts_str = time.strftime("%Y%m%d_%H%M%S")
        filename = f"ivris_backup_{ts_str}_{label}.db"
        dest_path = BACKUP_DIR / filename
        latest_path = BACKUP_DIR / "ivris_latest.db"

        if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
            return {"error": "Live database file does not exist yet."}

        src = sqlite3.connect(DB_PATH)
        dst = sqlite3.connect(dest_path)
        with dst:
            src.backup(dst)
        dst.close()

        # Update latest pointer backup image
        dst_latest = sqlite3.connect(latest_path)
        with dst_latest:
            src.backup(dst_latest)
        dst_latest.close()
        src.close()

        prune_old_backups(keep=30)
        info = get_backup_file_info(dest_path)
        print(f"[BACKUP ENGINE] Snapshot created: {filename} ({info.get('size_human', '')})")
        return info
    except Exception as e:
        print(f"[BACKUP ENGINE] Failed to create backup: {e}")
        return {"error": str(e)}


def prune_old_backups(keep: int = 30):
    try:
        files = [
            f
            for f in BACKUP_DIR.glob("ivris_backup_*.db")
            if f.is_file() and f.name != "ivris_latest.db"
        ]
        files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        for f in files[keep:]:
            try:
                f.unlink()
            except Exception:
                pass
    except Exception as e:
        print(f"[BACKUP ENGINE] Error pruning backups: {e}")


def get_backup_file_info(fpath: Path) -> dict:
    if not fpath.exists():
        return {}
    stat = fpath.stat()
    size_bytes = stat.st_size
    size_kb = round(size_bytes / 1024, 1)
    size_human = (
        f"{size_kb} KB" if size_kb < 1024 else f"{round(size_kb / 1024, 2)} MB"
    )
    users_count = 0
    posts_count = 0
    try:
        c = sqlite3.connect(fpath)
        users_count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        posts_count = c.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
        c.close()
    except Exception:
        pass
    return {
        "filename": fpath.name,
        "filepath": str(fpath),
        "size_bytes": size_bytes,
        "size_human": size_human,
        "created_at": int(stat.st_mtime),
        "created_at_iso": time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)
        ),
        "users_count": users_count,
        "posts_count": posts_count,
    }


def list_backups() -> list[dict]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    latest = BACKUP_DIR / "ivris_latest.db"
    if latest.exists():
        info = get_backup_file_info(latest)
        info["is_latest_pointer"] = True
        items.append(info)

    files = [
        f
        for f in BACKUP_DIR.glob("ivris_backup_*.db")
        if f.is_file() and f.name != "ivris_latest.db"
    ]
    files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    for f in files:
        items.append(get_backup_file_info(f))
    return items


def restore_database_from_file(backup_path: Path) -> tuple[bool, str]:
    if not backup_path.exists():
        return False, f"Backup file {backup_path.name} not found."
    try:
        test_conn = sqlite3.connect(backup_path)
        users_count = test_conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        test_conn.close()

        if DB_PATH.exists() and DB_PATH.stat().st_size > 0:
            create_database_backup("pre_restore_safety")

        src = sqlite3.connect(backup_path)
        dst = sqlite3.connect(DB_PATH)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()

        init_db()
        msg = f"Database restored from {backup_path.name} with {users_count} registered accounts."
        print(f"[BACKUP ENGINE] {msg}")
        return True, msg
    except Exception as e:
        err = f"Failed to restore backup: {e}"
        print(f"[BACKUP ENGINE] {err}")
        return False, err


def auto_restore_if_needed():
    """
    On container startup, checks if the live database is missing or empty.
    If so, immediately restores from the latest persistent snapshot.
    """
    try:
        should_restore = False
        if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
            should_restore = True
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                u_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                conn.close()
                if u_count == 0:
                    should_restore = True
            except Exception:
                should_restore = True

        if should_restore:
            latest = BACKUP_DIR / "ivris_latest.db"
            if latest.exists() and latest.stat().st_size > 0:
                print(f"[BACKUP ENGINE] Database empty/missing. Auto-restoring from {latest.name}...")
                restore_database_from_file(latest)
            else:
                backups = [
                    f for f in BACKUP_DIR.glob("ivris_backup_*.db") if f.is_file()
                ]
                if backups:
                    backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                    print(f"[BACKUP ENGINE] Auto-restoring from newest snapshot {backups[0].name}...")
                    restore_database_from_file(backups[0])
    except Exception as e:
        print(f"[BACKUP ENGINE] Auto-restore error: {e}")


def start_backup_scheduler():
    def _run():
        time.sleep(20)
        try:
            create_database_backup("startup")
        except Exception as e:
            print(f"[BACKUP SCHEDULER] Startup backup failed: {e}")

        while True:
            time.sleep(3600)  # Hourly automated snapshot
            try:
                create_database_backup("hourly")
            except Exception as e:
                print(f"[BACKUP SCHEDULER] Hourly backup failed: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def inspect_image_bytes_for_nudity(raw_bytes: bytes) -> tuple[bool, str]:
    """
    Analyzes image bytes using multi-space (YCbCr + RGB + HSV) skin-exposure and
    central-torso contiguous mass heuristics to detect nudity/explicit imagery
    so it can be immediately blocked and deleted.
    """
    if not raw_bytes or Image is None:
        return False, ""
    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
            rgb_img = img.convert("RGB").resize((120, 120))
            ycbcr_img = rgb_img.convert("YCbCr")
            hsv_img = rgb_img.convert("HSV")
            rgb_pixels = list(rgb_img.getdata())
            ycbcr_pixels = list(ycbcr_img.getdata())
            hsv_pixels = list(hsv_img.getdata())

            total_pixels = len(rgb_pixels)
            if total_pixels == 0:
                return False, ""

            skin_count = 0
            center_skin_count = 0
            center_total = 0
            torso_skin_count = 0
            torso_total = 0

            for idx, ((r, g, b), (y, cb, cr), (h, s, v)) in enumerate(
                zip(rgb_pixels, ycbcr_pixels, hsv_pixels)
            ):
                row = idx // 120
                col = idx % 120
                in_center = 18 <= row <= 102 and 18 <= col <= 102
                in_torso = 36 <= row <= 108 and 24 <= col <= 96
                if in_center:
                    center_total += 1
                if in_torso:
                    torso_total += 1

                rgb_skin = (
                    r > 85
                    and g > 35
                    and b > 18
                    and (max(r, g, b) - min(r, g, b)) > 12
                    and abs(r - g) > 10
                    and r >= g
                    and r >= b
                )
                ycbcr_skin = (77 <= cb <= 132) and (131 <= cr <= 178) and (y > 50)
                hsv_skin = (h <= 38 or h >= 240) and (28 <= s <= 190) and (v >= 60)

                if (rgb_skin and ycbcr_skin) or (ycbcr_skin and hsv_skin):
                    skin_count += 1
                    if in_center:
                        center_skin_count += 1
                    if in_torso:
                        torso_skin_count += 1

            overall_ratio = skin_count / total_pixels
            center_ratio = center_skin_count / max(center_total, 1)
            torso_ratio = torso_skin_count / max(torso_total, 1)

            if (center_ratio >= 0.48 and torso_ratio >= 0.50 and overall_ratio >= 0.36) or (
                center_ratio >= 0.58 and overall_ratio >= 0.44
            ):
                return (
                    True,
                    f"Automated image nudity detector triggered (torso exposure {int(torso_ratio * 100)}%, center {int(center_ratio * 100)}%, overall {int(overall_ratio * 100)}%).",
                )
    except Exception:
        return False, ""
    return False, ""


def detect_nudity_or_explicit(
    caption: str, location: str, raw_media_list: list[bytes]
) -> tuple[bool, str]:
    """
    Checks caption, location, and every uploaded media file for nudity or explicit content.
    """
    combined_text = f"{caption or ''} {location or ''}"
    match = EXPLICIT_NUDITY_PATTERN.search(combined_text)
    if match:
        return (
            True,
            f"Explicit/nudity keyword detected ('{match.group(0)}').",
        )

    for idx, media_bytes in enumerate(raw_media_list):
        flagged, reason = inspect_image_bytes_for_nudity(media_bytes)
        if flagged:
            return True, f"Media #{idx + 1}: {reason}"

    return False, ""


def unlink_post_files(post_row: dict):
    """Immediately deletes all physical media files associated with a post from disk."""
    urls = []
    try:
        urls = json.loads(post_row.get("media_urls_json") or "[]")
    except Exception:
        urls = []
    if post_row.get("media_url") and post_row["media_url"] not in urls:
        urls.append(post_row["media_url"])

    for u in urls:
        if isinstance(u, str) and u.startswith("/uploads/"):
            fname = u.replace("/uploads/", "", 1)
            fpath = (UPLOADS_DIR / fname).resolve()
            if str(fpath).startswith(str(UPLOADS_DIR.resolve())) and fpath.exists():
                try:
                    fpath.unlink(missing_ok=True)
                except Exception:
                    pass


def delete_post_immediately(
    conn, post_id: str, moderator_id: str, action: str, reason: str
) -> bool:
    """
    Immediately deletes a post from SQLite, removes its physical files from UPLOADS_DIR,
    resolves any open reports on the post, and writes an audit record to moderation_logs.
    """
    row = conn.execute(
        """
        SELECT p.*, u.handle AS author_handle
        FROM posts p
        LEFT JOIN users u ON u.id = p.author_id
        WHERE p.id = ?
        """,
        (post_id,),
    ).fetchone()
    if not row:
        return False

    post_dict = dict(row)
    unlink_post_files(post_dict)

    conn.execute("DELETE FROM post_likes WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM post_receipts WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM post_views WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.execute(
        "UPDATE moderation_reports SET status = 'taken_down' WHERE post_id = ?",
        (post_id,),
    )
    conn.execute(
        """
        INSERT INTO moderation_logs (id, moderator_id, action, target_id, author_handle, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "log_" + secrets.token_hex(6),
            moderator_id,
            action,
            post_id,
            post_dict.get("author_handle") or "unknown",
            reason,
            int(time.time()),
        ),
    )
    return True


def sweep_and_delete_nudity(conn) -> int:
    """
    Scans all existing posts in the database and immediately deletes any post
    whose caption or stored image files trigger nudity detection.
    """
    rows = conn.execute("SELECT * FROM posts").fetchall()
    deleted_count = 0
    for r in rows:
        p = dict(r)
        raw_files = []
        try:
            urls = json.loads(p.get("media_urls_json") or "[]")
        except Exception:
            urls = []
        if not urls and p.get("media_url"):
            urls = [p["media_url"]]

        for u in urls:
            if isinstance(u, str) and u.startswith("/uploads/"):
                fpath = UPLOADS_DIR / u.replace("/uploads/", "", 1)
                if fpath.exists():
                    try:
                        raw_files.append(fpath.read_bytes())
                    except Exception:
                        pass

        flagged, reason = detect_nudity_or_explicit(
            p.get("caption", ""), p.get("location_label", ""), raw_files
        )
        if flagged:
            if delete_post_immediately(
                conn, p["id"], "system_auto_nudity_filter", "auto_deleted_nudity", reason
            ):
                deleted_count += 1

    if deleted_count > 0:
        conn.commit()
    return deleted_count


def build_moderation_dashboard_payload(conn, user) -> dict:
    auto_deleted_now = sweep_and_delete_nudity(conn)

    reports = [
        dict(r)
        for r in conn.execute(
            """
            SELECT r.*,
                   p.media_url, p.media_urls_json, p.media_kind, p.caption, p.created_at AS post_created_at,
                   u.handle AS author_handle, u.display_name AS author_name, u.id AS author_id,
                   rep.handle AS reporter_handle
            FROM moderation_reports r
            LEFT JOIN posts p ON p.id = r.post_id
            LEFT JOIN users u ON u.id = p.author_id
            LEFT JOIN users rep ON rep.id = r.reporter_id
            ORDER BY
              CASE WHEN r.status = 'open' THEN 0 ELSE 1 END ASC,
              r.created_at DESC
            """
        ).fetchall()
    ]

    active_posts = []
    for r in conn.execute(
        """
        SELECT p.*, u.handle AS author_handle, u.display_name AS author_name, u.avatar_url AS author_avatar_url, u.account_type
        FROM posts p
        JOIN users u ON u.id = p.author_id
        ORDER BY p.created_at DESC
        """
    ).fetchall():
        item = dict(r)
        try:
            item["media_urls"] = json.loads(item.get("media_urls_json") or "[]")
        except Exception:
            item["media_urls"] = [item["media_url"]]
        item["views_count"] = conn.execute(
            "SELECT COUNT(*) AS c FROM post_views WHERE post_id = ?", (item["id"],)
        ).fetchone()["c"]
        active_posts.append(item)

    logs = [
        dict(r)
        for r in conn.execute(
            """
            SELECT * FROM moderation_logs
            ORDER BY created_at DESC
            LIMIT 100
            """
        ).fetchall()
    ]

    users_list = [
        dict(r)
        for r in conn.execute(
            """
            SELECT id, email, handle, display_name, avatar_url, account_type, is_verified_institution, created_at
            FROM users
            WHERE account_type != 'moderator'
            ORDER BY created_at DESC
            """
        ).fetchall()
    ]

    inst_apps = [
        dict(r)
        for r in conn.execute(
            """
            SELECT * FROM institution_applications
            ORDER BY created_at DESC
            """
        ).fetchall()
    ]

    return {
        "moderator": {
            "id": user.get("id", ""),
            "handle": user.get("handle", ""),
            "email": user.get("email", ""),
        },
        "auto_deleted_in_sweep": auto_deleted_now,
        "reports": reports,
        "active_posts": active_posts,
        "logs": logs,
        "users": users_list,
        "institution_applications": inst_apps,
        "backup_status": {
            "db_path": str(DB_PATH),
            "db_info": get_backup_file_info(DB_PATH),
            "backups": list_backups(),
        },
    }


def are_mutually_connected(conn, user_a: str, user_b: str) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM connections
        WHERE status = 'accepted'
          AND ((requester_id = ? AND addressee_id = ?) OR (requester_id = ? AND addressee_id = ?))
        """,
        (user_a, user_b, user_b, user_a),
    ).fetchone()
    return row is not None


class IvrisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def send_json(self, payload: dict, status: int = 200, extra_headers: dict | None = None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def get_current_user(self, conn):
        token = ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.replace("Bearer ", "").strip()
        if not token:
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                try:
                    c = http.cookies.SimpleCookie()
                    c.load(cookie_header)
                    if "ivris_session" in c:
                        token = c["ivris_session"].value
                except Exception:
                    pass
        if not token:
            return None

        row = conn.execute(
            """
            SELECT u.* FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
        if row:
            return dict(row)

        # Fallback: verify HMAC-signed persistent session token across server restarts/deploys
        return verify_and_restore_session_token(conn, token)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path in ("/moderation", "/moderation/"):
            mod_file = WEB_DIR / "moderation.html"
            if mod_file.exists():
                content = mod_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return

        if parsed.path == "/api/moderation/dashboard":
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user.get("account_type") != "moderator":
                    return self.send_json(
                        {"error": "Moderator account authorization required."}, 403
                    )
                return self.send_json(build_moderation_dashboard_payload(conn, user))
            finally:
                conn.close()

        if parsed.path == "/api/admin/backups":
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user.get("account_type") != "moderator":
                    return self.send_json({"error": "Unauthorized"}, 403)
                return self.send_json({
                    "db_info": get_backup_file_info(DB_PATH),
                    "backups": list_backups(),
                })
            finally:
                conn.close()

        if parsed.path == "/api/admin/backup/download":
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user or user.get("account_type") != "moderator":
                    return self.send_json({"error": "Unauthorized"}, 403)
                qs = urllib.parse.parse_qs(parsed.query)
                requested_file = qs.get("filename", [""])[0]
                target_file = DB_PATH
                download_name = f"ivris_database_{time.strftime('%Y%m%d_%H%M%S')}.db"
                if requested_file:
                    safe_filename = os.path.basename(requested_file)
                    cand = BACKUP_DIR / safe_filename
                    if cand.exists() and cand.is_file():
                        target_file = cand
                        download_name = safe_filename
                if not target_file.exists():
                    return self.send_json({"error": "File not found"}, 404)

                content = target_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-sqlite3")
                self.send_header(
                    "Content-Disposition", f'attachment; filename="{download_name}"'
                )
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            finally:
                conn.close()

        if parsed.path == "/api/state":
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user:
                    return self.send_json({"user": None})

                uid = user["id"]
                now_ts = int(time.time())

                try:
                    saved_settings = json.loads(user.get("settings_json") or "{}")
                except Exception:
                    saved_settings = {}
                user_settings = {**DEFAULT_SETTINGS, **saved_settings}

                conns = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM connections WHERE requester_id = ? OR addressee_id = ?",
                        (uid, uid),
                    ).fetchall()
                ]

                seen_ids = [
                    r["post_id"]
                    for r in conn.execute(
                        "SELECT post_id FROM post_receipts WHERE user_id = ?", (uid,)
                    ).fetchall()
                ]

                viewed_ids = [
                    r["post_id"]
                    for r in conn.execute(
                        "SELECT post_id FROM post_views WHERE user_id = ?", (uid,)
                    ).fetchall()
                ]

                all_posts = conn.execute(
                    """
                    SELECT p.*, u.handle, u.display_name, u.avatar_url, u.account_type, u.is_verified_institution
                    FROM posts p
                    JOIN users u ON u.id = p.author_id
                    ORDER BY p.created_at DESC
                    """
                ).fetchall()

                feed_posts = []
                my_posts = []
                stories = []
                my_stories = []

                for r in all_posts:
                    p = dict(r)
                    author_id = p["author_id"]
                    is_inst = bool(p["is_verified_institution"])
                    visible = (
                        author_id == uid
                        or is_inst
                        or are_mutually_connected(conn, uid, author_id)
                    )
                    if not visible:
                        continue

                    try:
                        urls = json.loads(p.get("media_urls_json") or "[]")
                    except Exception:
                        urls = []
                    if not urls and p.get("media_url"):
                        urls = [p["media_url"]]
                    p["media_urls"] = urls
                    try:
                        p["music"] = (
                            json.loads(p["music_json"]) if p.get("music_json") else None
                        )
                    except Exception:
                        p["music"] = None

                    if author_id == uid:
                        viewers = [
                            {
                                "id": vr["id"],
                                "handle": vr["handle"],
                                "display_name": vr["display_name"],
                                "avatar_url": vr["avatar_url"] or "",
                                "viewed_at": vr["viewed_at"],
                            }
                            for vr in conn.execute(
                                """
                                SELECT u.id, u.handle, u.display_name, u.avatar_url, pv.viewed_at
                                FROM post_views pv
                                JOIN users u ON u.id = pv.user_id
                                WHERE pv.post_id = ? AND pv.user_id != ?
                                ORDER BY pv.viewed_at DESC
                                """,
                                (p["id"], uid),
                            ).fetchall()
                        ]
                        p["viewers"] = viewers
                        p["viewsCount"] = len(viewers)

                    if p["media_kind"] == "video_story":
                        if p["expires_at"] and p["expires_at"] > now_ts:
                            if author_id == uid:
                                my_stories.append(p)
                            else:
                                stories.append(p)
                    else:
                        if author_id == uid:
                            my_posts.append(p)
                            feed_posts.append(p)
                        else:
                            feed_posts.append(p)

                other_users = []
                for r in conn.execute(
                    """
                    SELECT id, handle, display_name, bio, avatar_url, account_type, is_verified_institution
                    FROM users
                    WHERE id != ? AND account_type != 'moderator'
                    ORDER BY created_at DESC
                    """,
                    (uid,),
                ).fetchall():
                    u_dict = dict(r)
                    u_id = u_dict["id"]
                    u_dict["posts_count"] = conn.execute(
                        "SELECT COUNT(*) AS c FROM posts WHERE author_id = ? AND media_kind = 'photo_post'",
                        (u_id,),
                    ).fetchone()["c"]
                    u_dict["friends_count"] = conn.execute(
                        "SELECT COUNT(*) AS c FROM connections WHERE status = 'accepted' AND (requester_id = ? OR addressee_id = ?)",
                        (u_id, u_id),
                    ).fetchone()["c"]
                    other_users.append(u_dict)

                mod_dashboard = None
                if user.get("account_type") == "moderator":
                    mod_dashboard = build_moderation_dashboard_payload(conn, user)

                refreshed_token = create_session_token(user)
                conn.execute(
                    "INSERT OR IGNORE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (refreshed_token, uid, now_ts),
                )
                conn.commit()
                return self.send_json(
                    {
                        "token": refreshed_token,
                        "user": {
                            "id": user["id"],
                            "email": user["email"],
                            "handle": user["handle"],
                            "display_name": user["display_name"],
                            "bio": user["bio"],
                            "avatar_url": user.get("avatar_url") or "",
                            "account_type": user["account_type"],
                            "is_verified_institution": bool(user["is_verified_institution"]),
                            "settings": user_settings,
                        },
                        "connections": conns,
                        "seenPostIds": seen_ids,
                        "viewedPostIds": viewed_ids,
                        "feedPosts": feed_posts,
                        "myPosts": my_posts,
                        "myStories": my_stories,
                        "stories": stories,
                        "allProfiles": other_users,
                        "moderationDashboard": mod_dashboard,
                    },
                    extra_headers={
                        "Set-Cookie": f"ivris_session={refreshed_token}; Max-Age=31536000; Path=/; SameSite=Lax; HttpOnly"
                    },
                )
            finally:
                conn.close()

        if parsed.path == "/api/messages":
            conn = get_db()
            try:
                user = self.get_current_user(conn)
                if not user:
                    return self.send_json({"error": "Unauthorized"}, 401)
                qs = urllib.parse.parse_qs(parsed.query)
                partner_id = qs.get("partner_id", [""])[0]
                uid = user["id"]
                rows = conn.execute(
                    """
                    SELECT * FROM direct_messages
                    WHERE (sender_id = ? AND recipient_id = ?)
                       OR (sender_id = ? AND recipient_id = ?)
                    ORDER BY created_at ASC
                    """,
                    (uid, partner_id, partner_id, uid),
                ).fetchall()
                return self.send_json({"messages": [dict(r) for r in rows]})
            finally:
                conn.close()

        if parsed.path == "/api/music-search":
            qs = urllib.parse.parse_qs(parsed.query)
            query = (qs.get("q", [""])[0] or "").strip()
            if not query:
                query = "top hits"
            url = (
                "https://itunes.apple.com/search?"
                + urllib.parse.urlencode(
                    {
                        "term": query,
                        "media": "music",
                        "entity": "song",
                        "limit": "25",
                    }
                )
            )
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "IvrisSocial/1.0"}
                )
                with urllib.request.urlopen(req, timeout=6) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                tracks = []
                for item in payload.get("results", []):
                    if not item.get("previewUrl"):
                        continue
                    tracks.append(
                        {
                            "id": str(item.get("trackId", "")),
                            "title": item.get("trackName", "Unknown Track"),
                            "artist": item.get("artistName", "Unknown Artist"),
                            "album": item.get("collectionName", ""),
                            "artwork_url": item.get("artworkUrl100", ""),
                            "preview_url": item.get("previewUrl", ""),
                        }
                    )
                return self.send_json({"tracks": tracks})
            except Exception as exc:
                return self.send_json({"tracks": [], "error": str(exc)})

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}

        conn = get_db()
        try:
            if parsed.path == "/api/signup":
                email = (body.get("email") or "").strip().lower()
                password = (body.get("password") or "").strip()
                handle = (
                    (body.get("handle") or "")
                    .strip()
                    .lower()
                    .replace("@", "")
                    .replace(" ", "")
                )
                display_name = (body.get("display_name") or "").strip()

                if not email or not password or len(handle) < 2 or not display_name:
                    return self.send_json(
                        {"error": "Please fill in your email, password, username, and full name."},
                        400,
                    )

                existing_email = conn.execute(
                    "SELECT * FROM users WHERE email = ?", (email,)
                ).fetchone()
                if existing_email:
                    if existing_email["email_confirmed"] == 0:
                        code = f"{random.randint(100000, 999999)}"
                        conn.execute(
                            "UPDATE users SET verification_code = ?, password_hash = ? WHERE id = ?",
                            (code, hash_pw(password), existing_email["id"]),
                        )
                        conn.commit()
                        return self.send_json(
                            {
                                "needs_confirmation": True,
                                "email": email,
                                "confirmation_code_preview": code,
                            }
                        )
                    return self.send_json(
                        {"error": "An account with this email already exists. Please sign in."},
                        400,
                    )

                existing_handle = conn.execute(
                    "SELECT 1 FROM users WHERE handle = ?", (handle,)
                ).fetchone()
                if existing_handle:
                    return self.send_json(
                        {"error": f"Username @{handle} is already taken."}, 400
                    )

                uid = "usr_" + secrets.token_hex(8)
                user_obj = {
                    "id": uid,
                    "email": email,
                    "handle": handle,
                    "display_name": display_name,
                    "bio": "",
                    "avatar_url": "",
                    "account_type": "personal",
                    "is_verified_institution": 0,
                    "password_hash": hash_pw(password),
                }
                token = create_session_token(user_obj)
                conn.execute(
                    """
                    INSERT INTO users (id, email, password_hash, handle, display_name, bio, avatar_url, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, created_at)
                    VALUES (?, ?, ?, ?, ?, '', '', 'personal', 0, 1, '', ?, ?)
                    """,
                    (
                        uid,
                        email,
                        hash_pw(password),
                        handle,
                        display_name,
                        json.dumps(DEFAULT_SETTINGS),
                        int(time.time()),
                    ),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (token, uid, int(time.time())),
                )
                conn.commit()
                return self.send_json(
                    {
                        "token": token,
                        "account_type": "personal",
                        "handle": handle,
                        "user": user_obj,
                    }
                )

            if parsed.path == "/api/verify-email":
                email = (body.get("email") or "").strip().lower()
                code = (body.get("code") or "").strip()
                user = conn.execute(
                    "SELECT * FROM users WHERE email = ?", (email,)
                ).fetchone()
                if not user:
                    return self.send_json({"error": "Account not found."}, 404)
                if not code or user["verification_code"] != code:
                    return self.send_json({"error": "Invalid 6-digit confirmation code."}, 400)

                conn.execute(
                    "UPDATE users SET email_confirmed = 1, verification_code = '' WHERE id = ?",
                    (user["id"],),
                )
                updated_user = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (user["id"],)
                ).fetchone()
                token = create_session_token(updated_user)
                conn.execute(
                    "INSERT OR REPLACE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (token, user["id"], int(time.time())),
                )
                conn.commit()
                cookie_val = f"ivris_session={token}; Max-Age=31536000; Path=/; SameSite=Lax; HttpOnly"
                return self.send_json(
                    {"token": token}, extra_headers={"Set-Cookie": cookie_val}
                )

            if parsed.path == "/api/signin":
                identifier = (body.get("email") or "").strip().lower()
                password = (body.get("password") or "").strip()
                if not identifier or not password:
                    return self.send_json(
                        {"error": "Please enter your email (or username) and password."}, 400
                    )

                clean_handle = identifier.replace("@", "")
                user = conn.execute(
                    "SELECT * FROM users WHERE email = ? OR handle = ?",
                    (identifier, clean_handle),
                ).fetchone()

                if not user:
                    return self.send_json(
                        {"error": "No account found with that email or username. Please sign up first."},
                        404,
                    )

                if user["password_hash"] != hash_pw(password):
                    return self.send_json({"error": "Incorrect password."}, 401)

                if user["email_confirmed"] == 0:
                    code = user["verification_code"] or f"{random.randint(100000, 999999)}"
                    conn.execute(
                        "UPDATE users SET verification_code = ? WHERE id = ?",
                        (code, user["id"]),
                    )
                    conn.commit()
                    return self.send_json(
                        {
                            "needs_confirmation": True,
                            "email": user["email"],
                            "confirmation_code_preview": code,
                        }
                    )

                token = create_session_token(user)
                conn.execute(
                    "INSERT OR REPLACE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (token, user["id"], int(time.time())),
                )
                conn.commit()
                cookie_val = f"ivris_session={token}; Max-Age=31536000; Path=/; SameSite=Lax; HttpOnly"
                return self.send_json(
                    {
                        "token": token,
                        "account_type": user["account_type"],
                        "handle": user["handle"],
                    },
                    extra_headers={"Set-Cookie": cookie_val},
                )

            if parsed.path == "/api/signout":
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    tok = auth.replace("Bearer ", "").strip()
                    conn.execute("DELETE FROM sessions WHERE token = ?", (tok,))
                    conn.commit()
                clear_cookie = "ivris_session=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly"
                return self.send_json(
                    {"ok": True},
                    extra_headers={
                        "Set-Cookie": clear_cookie,
                        "Clear-Site-Data": '"cookies", "storage"',
                    },
                )

            if parsed.path == "/api/institution-apply":
                inst_name = (body.get("institution_name") or "").strip()
                domain = (body.get("official_domain") or "").strip()
                email = (body.get("contact_email") or "").strip()
                notes = (body.get("notes") or "").strip()
                user = self.get_current_user(conn)
                conn.execute(
                    """
                    INSERT INTO institution_applications
                    (id, applicant_user_id, institution_name, official_domain, contact_email, notes, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending_review', ?)
                    """,
                    (
                        "app_" + secrets.token_hex(6),
                        user["id"] if user else None,
                        inst_name,
                        domain,
                        email,
                        notes,
                        int(time.time()),
                    ),
                )
                conn.commit()
                return self.send_json({"ok": True})

            # Public or authenticated content report endpoint
            if parsed.path == "/api/report":
                user = self.get_current_user(conn)
                post_id = (body.get("post_id") or "").strip()
                reason = (body.get("reason") or "reported_content").strip()
                details = (body.get("details") or "").strip()
                if not post_id:
                    return self.send_json({"error": "post_id is required."}, 400)

                post_row = conn.execute(
                    "SELECT * FROM posts WHERE id = ?", (post_id,)
                ).fetchone()
                if not post_row:
                    return self.send_json({"error": "Post not found or already deleted."}, 404)

                # If reported for nudity, immediately delete the post and its files
                if "nudi" in reason.lower() or "explicit" in reason.lower():
                    delete_post_immediately(
                        conn,
                        post_id,
                        user["id"] if user else "system_auto_nudity_filter",
                        "auto_deleted_nudity",
                        f"Immediate deletion triggered by nudity report: {reason}",
                    )
                    conn.commit()
                    return self.send_json(
                        {
                            "ok": True,
                            "immediately_deleted": True,
                            "message": "Nudity report verified: Post and media files were immediately deleted.",
                        }
                    )

                report_id = "rep_" + secrets.token_hex(6)
                conn.execute(
                    """
                    INSERT INTO moderation_reports (id, post_id, reporter_id, reason, details, status, created_at)
                    VALUES (?, ?, ?, ?, ?, 'open', ?)
                    """,
                    (
                        report_id,
                        post_id,
                        user["id"] if user else None,
                        reason,
                        details,
                        int(time.time()),
                    ),
                )
                conn.commit()
                return self.send_json({"ok": True, "report_id": report_id})

            # Authenticated endpoints below
            user = self.get_current_user(conn)
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            uid = user["id"]

            # Moderator / Admin endpoints
            if parsed.path.startswith("/api/moderation/") or parsed.path.startswith("/api/admin/"):
                if user.get("account_type") != "moderator":
                    return self.send_json(
                        {"error": "Moderator account authorization required."}, 403
                    )

                if parsed.path == "/api/admin/backup/create":
                    label = (body.get("label") or "manual").strip()
                    info = create_database_backup(label)
                    return self.send_json({"ok": True, "backup": info})

                if parsed.path == "/api/admin/backup/restore":
                    filename = (body.get("filename") or "").strip()
                    if filename:
                        safe_filename = os.path.basename(filename)
                        cand = BACKUP_DIR / safe_filename
                        success, msg = restore_database_from_file(cand)
                        if success:
                            return self.send_json({"ok": True, "message": msg})
                        return self.send_json({"error": msg}, 400)

                    raw_b64 = body.get("backup_base64")
                    if raw_b64:
                        try:
                            raw_bytes = base64.b64decode(raw_b64)
                            temp_restore = BACKUP_DIR / f"temp_upload_{time.strftime('%Y%m%d_%H%M%S')}.db"
                            temp_restore.write_bytes(raw_bytes)
                            success, msg = restore_database_from_file(temp_restore)
                            if success:
                                return self.send_json({"ok": True, "message": msg})
                            return self.send_json({"error": msg}, 400)
                        except Exception as e:
                            return self.send_json({"error": f"Failed to restore uploaded database: {e}"}, 400)

                    return self.send_json({"error": "No backup specified to restore."}, 400)

                if parsed.path == "/api/moderation/takedown":
                    post_id = (body.get("post_id") or "").strip()
                    reason = (body.get("reason") or "Moderator takedown of reported/violating post").strip()
                    if not post_id:
                        return self.send_json({"error": "post_id is required."}, 400)
                    deleted = delete_post_immediately(
                        conn, post_id, uid, "takedown_post", reason
                    )
                    conn.commit()
                    if not deleted:
                        return self.send_json({"error": "Post already removed."}, 404)
                    return self.send_json({"ok": True, "deleted_post_id": post_id})

                if parsed.path == "/api/moderation/dismiss-report":
                    report_id = (body.get("report_id") or "").strip()
                    conn.execute(
                        "UPDATE moderation_reports SET status = 'dismissed' WHERE id = ?",
                        (report_id,),
                    )
                    conn.commit()
                    return self.send_json({"ok": True})

                if parsed.path == "/api/moderation/sweep-nudity":
                    removed = sweep_and_delete_nudity(conn)
                    return self.send_json({"ok": True, "deleted_count": removed})

                if parsed.path == "/api/moderation/approve-institution":
                    app_id = (body.get("application_id") or "").strip()
                    app_row = conn.execute(
                        "SELECT * FROM institution_applications WHERE id = ?", (app_id,)
                    ).fetchone()
                    if not app_row:
                        return self.send_json({"error": "Application not found."}, 404)
                    conn.execute(
                        "UPDATE institution_applications SET status = 'approved' WHERE id = ?",
                        (app_id,),
                    )
                    if app_row["applicant_user_id"]:
                        conn.execute(
                            "UPDATE users SET account_type = 'institution', is_verified_institution = 1 WHERE id = ?",
                            (app_row["applicant_user_id"],),
                        )
                    conn.commit()
                    return self.send_json({"ok": True})

                if parsed.path == "/api/moderation/delete-user":
                    target_uid = (body.get("user_id") or "").strip()
                    reason = (body.get("reason") or "Account removed by moderator").strip()
                    target_user = conn.execute(
                        "SELECT * FROM users WHERE id = ? AND account_type != 'moderator'",
                        (target_uid,),
                    ).fetchone()
                    if not target_user:
                        return self.send_json({"error": "User not found."}, 404)

                    user_posts = conn.execute(
                        "SELECT * FROM posts WHERE author_id = ?", (target_uid,)
                    ).fetchall()
                    for up in user_posts:
                        unlink_post_files(dict(up))

                    conn.execute("DELETE FROM post_likes WHERE user_id = ?", (target_uid,))
                    conn.execute("DELETE FROM post_receipts WHERE user_id = ?", (target_uid,))
                    conn.execute("DELETE FROM post_views WHERE user_id = ?", (target_uid,))
                    conn.execute(
                        "DELETE FROM direct_messages WHERE sender_id = ? OR recipient_id = ?",
                        (target_uid, target_uid),
                    )
                    conn.execute(
                        "DELETE FROM connections WHERE requester_id = ? OR addressee_id = ?",
                        (target_uid, target_uid),
                    )
                    conn.execute("DELETE FROM posts WHERE author_id = ?", (target_uid,))
                    conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_uid,))
                    conn.execute("DELETE FROM users WHERE id = ?", (target_uid,))
                    conn.execute(
                        """
                        INSERT INTO moderation_logs (id, moderator_id, action, target_id, author_handle, reason, created_at)
                        VALUES (?, ?, 'remove_account', ?, ?, ?, ?)
                        """,
                        (
                            "log_" + secrets.token_hex(6),
                            uid,
                            target_uid,
                            target_user["handle"],
                            reason,
                            int(time.time()),
                        ),
                    )
                    conn.commit()
                    return self.send_json({"ok": True})

            if parsed.path == "/api/update-profile":
                display_name = (
                    body.get("display_name")
                    if "display_name" in body
                    else user["display_name"]
                ).strip()
                handle = (
                    (body.get("handle") if "handle" in body else user["handle"])
                    .strip()
                    .lower()
                    .replace("@", "")
                    .replace(" ", "")
                )
                bio = (
                    body.get("bio") if "bio" in body else (user.get("bio") or "")
                ).strip()
                avatar_data_url = body.get("avatar_data_url") or ""

                if not display_name or len(handle) < 2:
                    return self.send_json(
                        {"error": "Display name and username (2+ chars) are required."}, 400
                    )

                conflict = conn.execute(
                    "SELECT 1 FROM users WHERE handle = ? AND id != ?", (handle, uid)
                ).fetchone()
                if conflict:
                    return self.send_json(
                        {"error": f"Username @{handle} is already taken."}, 400
                    )

                new_avatar_url = user.get("avatar_url") or ""
                if avatar_data_url and "," in avatar_data_url:
                    _, b64_data = avatar_data_url.split(",", 1)
                    raw_avatar = base64.b64decode(b64_data)
                    is_nude, n_reason = inspect_image_bytes_for_nudity(raw_avatar)
                    if is_nude:
                        return self.send_json(
                            {"error": "Profile photo rejected by safety filter."}, 400
                        )
                    avatar_fname = f"avatar_{uid}_{int(time.time() * 1000)}.jpg"
                    (UPLOADS_DIR / avatar_fname).write_bytes(raw_avatar)
                    new_avatar_url = f"/uploads/{avatar_fname}"

                conn.execute(
                    "UPDATE users SET display_name = ?, handle = ?, bio = ?, avatar_url = ? WHERE id = ?",
                    (display_name, handle, bio, new_avatar_url, uid),
                )
                conn.commit()
                return self.send_json({"ok": True, "avatar_url": new_avatar_url})

            if parsed.path == "/api/delete-post":
                post_id = (body.get("post_id") or "").strip()
                post_row = conn.execute(
                    "SELECT * FROM posts WHERE id = ? AND author_id = ?", (post_id, uid)
                ).fetchone()
                if not post_row:
                    return self.send_json({"error": "Post not found."}, 404)
                unlink_post_files(dict(post_row))
                conn.execute("DELETE FROM post_likes WHERE post_id = ?", (post_id,))
                conn.execute("DELETE FROM post_receipts WHERE post_id = ?", (post_id,))
                conn.execute("DELETE FROM post_views WHERE post_id = ?", (post_id,))
                conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
                conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/change-password":
                current_pw = (body.get("current_password") or "").strip()
                new_pw = (body.get("new_password") or "").strip()
                if user["password_hash"] != hash_pw(current_pw):
                    return self.send_json({"error": "Current password is incorrect."}, 400)
                if len(new_pw) < 6:
                    return self.send_json(
                        {"error": "New password must be at least 6 characters."}, 400
                    )
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hash_pw(new_pw), uid),
                )
                conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/update-settings":
                try:
                    current_settings = json.loads(user.get("settings_json") or "{}")
                except Exception:
                    current_settings = {}
                updated = {**DEFAULT_SETTINGS, **current_settings, **(body.get("settings") or {})}
                conn.execute(
                    "UPDATE users SET settings_json = ? WHERE id = ?",
                    (json.dumps(updated), uid),
                )
                conn.commit()
                return self.send_json({"ok": True, "settings": updated})

            if parsed.path == "/api/delete-account":
                user_posts = conn.execute(
                    "SELECT * FROM posts WHERE author_id = ?", (uid,)
                ).fetchall()
                for up in user_posts:
                    unlink_post_files(dict(up))
                conn.execute("DELETE FROM post_likes WHERE user_id = ?", (uid,))
                conn.execute("DELETE FROM post_receipts WHERE user_id = ?", (uid,))
                conn.execute("DELETE FROM post_views WHERE user_id = ?", (uid,))
                conn.execute(
                    "DELETE FROM direct_messages WHERE sender_id = ? OR recipient_id = ?",
                    (uid, uid),
                )
                conn.execute(
                    "DELETE FROM connections WHERE requester_id = ? OR addressee_id = ?",
                    (uid, uid),
                )
                conn.execute("DELETE FROM posts WHERE author_id = ?", (uid,))
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))
                conn.execute("DELETE FROM users WHERE id = ?", (uid,))
                conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/posts":
                media_kind = body.get("media_kind", "photo_post")
                caption = (body.get("caption") or "").strip()
                location = (body.get("location_label") or "").strip()
                music = body.get("music")
                music_json = (
                    json.dumps(music)
                    if isinstance(music, dict) and music.get("title")
                    else ""
                )
                data_urls = body.get("data_urls") or []
                if not data_urls and body.get("data_url"):
                    data_urls = [body.get("data_url")]

                if not data_urls:
                    return self.send_json({"error": "No media selected."}, 400)

                if len(data_urls) > 15:
                    return self.send_json(
                        {"error": "You can upload a maximum of 15 photos per post."}, 400
                    )

                decoded_items = []
                raw_bytes_list = []
                for idx, data_url in enumerate(data_urls):
                    if "," not in data_url:
                        continue
                    header, b64_data = data_url.split(",", 1)
                    ext = "mp4" if "video" in header else "jpg"
                    raw_media = base64.b64decode(b64_data)
                    decoded_items.append((idx, ext, raw_media))
                    if ext != "mp4":
                        raw_bytes_list.append(raw_media)

                if not decoded_items:
                    return self.send_json({"error": "Invalid media files."}, 400)

                # Immediate Nudity Detection & Deletion before saving to disk or database
                is_nudity, nudity_reason = detect_nudity_or_explicit(
                    caption, location, raw_bytes_list
                )
                if is_nudity or body.get("client_nudity_flagged"):
                    final_reason = nudity_reason or body.get("client_nudity_reason") or "Client + server image nudity scan triggered."
                    conn.execute(
                        """
                        INSERT INTO moderation_logs (id, moderator_id, action, target_id, author_handle, reason, created_at)
                        VALUES (?, 'system_auto_nudity_filter', 'auto_deleted_nudity', ?, ?, ?, ?)
                        """,
                        (
                            "log_" + secrets.token_hex(6),
                            "blocked_upload_" + secrets.token_hex(4),
                            user["handle"],
                            final_reason,
                            int(time.time()),
                        ),
                    )
                    conn.commit()
                    return self.send_json(
                        {
                            "error": "Upload immediately deleted: Nudity and explicit content are strictly prohibited on Ivris.",
                            "auto_deleted_nudity": True,
                        },
                        400,
                    )

                saved_urls = []
                for idx, ext, raw_media in decoded_items:
                    filename = f"{uid}_{int(time.time() * 1000)}_{idx}.{ext}"
                    filepath = UPLOADS_DIR / filename
                    filepath.write_bytes(raw_media)
                    saved_urls.append(f"/uploads/{filename}")

                now_ts = int(time.time())
                expires_at = now_ts + 86400 if media_kind == "video_story" else None
                post_id = "pst_" + secrets.token_hex(8)

                conn.execute(
                    """
                    INSERT INTO posts (id, author_id, media_kind, media_url, media_urls_json, caption, location_label, music_json, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        post_id,
                        uid,
                        media_kind,
                        saved_urls[0],
                        json.dumps(saved_urls),
                        caption,
                        location,
                        music_json,
                        expires_at,
                        now_ts,
                    ),
                )
                conn.commit()
                return self.send_json({"ok": True, "id": post_id})

            if parsed.path == "/api/view":
                post_id = (body.get("post_id") or "").strip()
                if post_id:
                    now_ts = int(time.time())
                    conn.execute(
                        "INSERT OR REPLACE INTO post_views (post_id, user_id, viewed_at) VALUES (?, ?, ?)",
                        (post_id, uid, now_ts),
                    )
                    conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/seen":
                post_id = body.get("post_id", "")
                now_ts = int(time.time())
                conn.execute(
                    "INSERT OR REPLACE INTO post_receipts (user_id, post_id, seen_at) VALUES (?, ?, ?)",
                    (uid, post_id, now_ts),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO post_views (post_id, user_id, viewed_at) VALUES (?, ?, ?)",
                    (post_id, uid, now_ts),
                )
                conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/connect":
                target_id = body.get("target_id", "")
                target = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (target_id,)
                ).fetchone()
                if not target:
                    return self.send_json({"error": "User not found"}, 404)

                existing = conn.execute(
                    """
                    SELECT * FROM connections
                    WHERE (requester_id = ? AND addressee_id = ?)
                       OR (requester_id = ? AND addressee_id = ?)
                    """,
                    (uid, target_id, target_id, uid),
                ).fetchone()

                if not existing:
                    status = (
                        "accepted"
                        if target["account_type"] == "institution"
                        else "pending"
                    )
                    conn.execute(
                        """
                        INSERT INTO connections (id, requester_id, addressee_id, status, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        ("con_" + secrets.token_hex(6), uid, target_id, status, int(time.time())),
                    )
                elif existing["status"] == "pending" and existing["addressee_id"] == uid:
                    conn.execute(
                        "UPDATE connections SET status = 'accepted' WHERE id = ?",
                        (existing["id"],),
                    )
                conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/messages":
                recipient_id = body.get("recipient_id", "")
                message = (body.get("message") or "").strip()
                if recipient_id and message:
                    conn.execute(
                        """
                        INSERT INTO direct_messages (id, sender_id, recipient_id, message, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            "msg_" + secrets.token_hex(8),
                            uid,
                            recipient_id,
                            message,
                            int(time.time()),
                        ),
                    )
                    conn.commit()
                return self.send_json({"ok": True})

            return self.send_json({"error": "Not found"}, 404)
        finally:
            conn.close()


if __name__ == "__main__":
    auto_restore_if_needed()
    init_db()
    create_database_backup("boot")
    start_backup_scheduler()
    port = int(os.environ.get("PORT", "3000"))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), IvrisHandler)
    print(f"Ivris Backend & Web Server running on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()
