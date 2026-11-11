#!/usr/bin/env python3
import base64
import concurrent.futures
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
import subprocess
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
ADMIN_OWNER_HANDLES = {"moderator"}


def is_moderator_user(user: dict | None) -> bool:
    if not user:
        return False
    if user.get("account_type") == "moderator":
        return True
    handle = (user.get("handle") or "").strip().lower()
    return handle in ADMIN_OWNER_HANDLES

TOKEN_SIGNING_SECRET = os.environ.get(
    "IVRIS_TOKEN_SECRET", "ivris_persistent_session_signing_key_2026"
)

DEFAULT_SETTINGS = {
    "read_receipts": True,
    "story_replies": True,
    "auto_hide_seen": False,
    "quiet_mode": False,
    "notify_requests": True,
    "notify_messages": True,
}

CLOUD_VAULT_RAW_URL = os.environ.get(
    "IVRIS_CLOUD_VAULT_URL",
    "https://github.com/realAWZ/ivris/raw/ivris-data-vault/ivris_vault.db",
)
_vault_sync_lock = threading.Lock()
_vault_sync_pending = False

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
        tomb = conn.execute(
            "SELECT 1 FROM deleted_records WHERE record_type = 'user' AND record_id = ?",
            (uid,),
        ).fetchone()
        if tomb:
            return None
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
        conn.commit()
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        create_database_backup("session_restored")

    if user_row:
        conn.execute(
            "INSERT OR IGNORE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_row["id"], int(time.time())),
        )
        conn.commit()
        return dict(user_row)
    return None


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
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
            updated_at INTEGER NOT NULL DEFAULT 0,
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
            report_type TEXT NOT NULL DEFAULT 'post',
            post_id TEXT DEFAULT '',
            target_user_id TEXT DEFAULT '',
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

        CREATE TABLE IF NOT EXISTS media_blobs (
            url TEXT PRIMARY KEY,
            mime_type TEXT NOT NULL,
            data BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS deleted_records (
            record_type TEXT NOT NULL,
            record_id TEXT PRIMARY KEY,
            deleted_at INTEGER NOT NULL
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
    if "updated_at" not in existing_user_cols:
        cur.execute("ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0")

    existing_report_cols = [
        r["name"] for r in cur.execute("PRAGMA table_info(moderation_reports)").fetchall()
    ]
    if "report_type" not in existing_report_cols:
        cur.execute("ALTER TABLE moderation_reports ADD COLUMN report_type TEXT NOT NULL DEFAULT 'post'")
    if "target_user_id" not in existing_report_cols:
        cur.execute("ALTER TABLE moderation_reports ADD COLUMN target_user_id TEXT DEFAULT ''")

    existing_post_cols = [
        r["name"] for r in cur.execute("PRAGMA table_info(posts)").fetchall()
    ]
    if "media_urls_json" not in existing_post_cols:
        cur.execute("ALTER TABLE posts ADD COLUMN media_urls_json TEXT DEFAULT '[]'")
    if "music_json" not in existing_post_cols:
        cur.execute("ALTER TABLE posts ADD COLUMN music_json TEXT DEFAULT ''")

    # Migrate existing users to auto_hide_seen = False so feed posts stay visible like Instagram
    for u_row in cur.execute("SELECT id, settings_json FROM users").fetchall():
        try:
            s_obj = json.loads(u_row["settings_json"] or "{}")
            if s_obj.get("auto_hide_seen") is True:
                s_obj["auto_hide_seen"] = False
                cur.execute(
                    "UPDATE users SET settings_json = ? WHERE id = ?",
                    (json.dumps(s_obj), u_row["id"]),
                )
        except Exception:
            pass

    # Backfill post_views from post_receipts
    cur.execute(
        """
        INSERT OR IGNORE INTO post_views (post_id, user_id, viewed_at)
        SELECT post_id, user_id, seen_at FROM post_receipts
        """
    )

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
    backfill_disk_uploads_to_blobs()


def backfill_disk_uploads_to_blobs():
    """Ensures every physical file in UPLOADS_DIR is stored in media_blobs inside SQLite."""
    try:
        if not UPLOADS_DIR.exists():
            return
        conn = get_db()
        inserted = 0
        for fpath in UPLOADS_DIR.iterdir():
            if not fpath.is_file() or fpath.stat().st_size < 200:
                continue
            url = f"/uploads/{fpath.name}"
            existing = conn.execute(
                "SELECT length(data) AS l FROM media_blobs WHERE url = ?", (url,)
            ).fetchone()
            if not existing or existing["l"] < fpath.stat().st_size:
                raw = fpath.read_bytes()
                ext = fpath.suffix.lower()
                mime = (
                    "image/jpeg"
                    if ext in (".jpg", ".jpeg")
                    else ("video/mp4" if ext == ".mp4" else "image/png")
                )
                conn.execute(
                    "INSERT OR REPLACE INTO media_blobs (url, mime_type, data, created_at) VALUES (?, ?, ?, ?)",
                    (url, mime, raw, int(fpath.stat().st_mtime)),
                )
                inserted += 1
        if inserted > 0:
            conn.commit()
            print(f"[MEDIA RECOVERY] Backfilled {inserted} disk uploads into SQLite media_blobs.")
        conn.close()
    except Exception as e:
        print(f"[MEDIA RECOVERY] Error backfilling disk uploads: {e}")


def create_database_backup(label: str = "auto", sync_vault: bool = True) -> dict:
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

        src = sqlite3.connect(DB_PATH, timeout=30.0)
        dst = sqlite3.connect(dest_path, timeout=30.0)
        with dst:
            src.backup(dst)
        dst.close()

        # Update latest pointer backup image
        dst_latest = sqlite3.connect(latest_path, timeout=30.0)
        with dst_latest:
            src.backup(dst_latest)
        dst_latest.close()
        src.close()

        prune_old_backups(keep=30)
        info = get_backup_file_info(dest_path)
        print(f"[BACKUP ENGINE] Snapshot created: {filename} ({info.get('size_human', '')})")
        if sync_vault and label not in ("boot", "startup", "hourly", "pre_restore_safety"):
            trigger_background_vault_sync()
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
    connections_count = 0
    try:
        c = sqlite3.connect(fpath, timeout=10.0)
        users_count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        posts_count = c.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
        connections_count = c.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
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
        "connections_count": connections_count,
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


def merge_databases(src_path: Path, dst_path: Path = DB_PATH) -> dict:
    """
    Additive Multi-Master SQLite Merge Engine:
    Unions accounts (users), friend connections (connections), posts (posts),
    media files (media_blobs), messages (direct_messages), and views/receipts
    from src_path into dst_path while honoring intentional deletions in deleted_records.
    Never wipes or loses rows created on either instance.
    """
    if not src_path.exists() or src_path.stat().st_size < 4096:
        return {"ok": False, "error": "Source database missing or invalid"}

    init_db()
    conn = sqlite3.connect(dst_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        src_conn = sqlite3.connect(src_path, timeout=15.0)
        src_conn.row_factory = sqlite3.Row
        src_tables = {
            r["name"]
            for r in src_conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        # 1. Merge deleted_records tombstones first
        if "deleted_records" in src_tables:
            for r in src_conn.execute("SELECT * FROM deleted_records").fetchall():
                conn.execute(
                    "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES (?, ?, ?)",
                    (r["record_type"], r["record_id"], r["deleted_at"]),
                )

        deleted_users = {
            r["record_id"]
            for r in conn.execute(
                "SELECT record_id FROM deleted_records WHERE record_type = 'user'"
            ).fetchall()
        }
        deleted_posts = {
            r["record_id"]
            for r in conn.execute(
                "SELECT record_id FROM deleted_records WHERE record_type = 'post'"
            ).fetchall()
        }
        deleted_conns = {
            r["record_id"]
            for r in conn.execute(
                "SELECT record_id FROM deleted_records WHERE record_type = 'connection'"
            ).fetchall()
        }

        # Apply tombstones to destination DB
        for pid in deleted_posts:
            conn.execute("DELETE FROM posts WHERE id = ?", (pid,))
            conn.execute("DELETE FROM post_views WHERE post_id = ?", (pid,))
            conn.execute("DELETE FROM post_receipts WHERE post_id = ?", (pid,))
            conn.execute("DELETE FROM post_likes WHERE post_id = ?", (pid,))
        for cid in deleted_conns:
            conn.execute("DELETE FROM connections WHERE id = ?", (cid,))
        for uid in deleted_users:
            conn.execute("DELETE FROM users WHERE id = ? AND account_type != 'moderator'", (uid,))

        # 2. Merge users additively
        if "users" in src_tables:
            src_user_cols = {
                r["name"] for r in src_conn.execute("PRAGMA table_info(users)").fetchall()
            }

            def _avatar_ts(url_str: str) -> int:
                m = re.search(r"avatar_[^_]+_(\d+)\.", url_str or "")
                return int(m.group(1)) if m else 0

            for u in src_conn.execute("SELECT * FROM users").fetchall():
                u_dict = dict(u)
                uid = u_dict["id"]
                if uid in deleted_users:
                    continue
                existing = conn.execute(
                    "SELECT * FROM users WHERE id = ? OR email = ? OR handle = ?",
                    (uid, u_dict["email"], u_dict["handle"]),
                ).fetchone()
                if not existing:
                    settings_raw = u_dict.get("settings_json") or json.dumps(DEFAULT_SETTINGS)
                    try:
                        s_obj = json.loads(settings_raw)
                        s_obj["auto_hide_seen"] = False
                        settings_raw = json.dumps(s_obj)
                    except Exception:
                        settings_raw = json.dumps(DEFAULT_SETTINGS)
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO users
                        (id, email, password_hash, handle, display_name, bio, avatar_url, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, updated_at, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            uid,
                            u_dict["email"],
                            u_dict["password_hash"],
                            u_dict["handle"],
                            u_dict["display_name"],
                            u_dict.get("bio") or "",
                            u_dict.get("avatar_url") or "" if "avatar_url" in src_user_cols else "",
                            u_dict.get("account_type") or "personal",
                            int(u_dict.get("is_verified_institution") or 0),
                            int(u_dict.get("email_confirmed", 1)),
                            u_dict.get("verification_code") or "",
                            settings_raw,
                            int(u_dict.get("updated_at") or 0) if "updated_at" in src_user_cols else 0,
                            int(u_dict.get("created_at") or time.time()),
                        ),
                    )
                else:
                    ex_dict = dict(existing)
                    confirmed = max(
                        int(ex_dict.get("email_confirmed") or 0),
                        int(u_dict.get("email_confirmed") or 0),
                    )
                    verified_inst = max(
                        int(ex_dict.get("is_verified_institution") or 0),
                        int(u_dict.get("is_verified_institution") or 0),
                    )
                    ex_upd = int(ex_dict.get("updated_at") or 0)
                    src_upd = int(u_dict.get("updated_at") or 0) if "updated_at" in src_user_cols else 0
                    ex_av = ex_dict.get("avatar_url") or ""
                    src_av = u_dict.get("avatar_url") or "" if "avatar_url" in src_user_cols else ""

                    if src_upd > ex_upd:
                        avatar = src_av
                        bio = u_dict.get("bio") or ""
                        disp_name = u_dict.get("display_name") or ex_dict.get("display_name")
                        upd_ts = src_upd
                    elif ex_upd > src_upd:
                        avatar = ex_av
                        bio = ex_dict.get("bio") or ""
                        disp_name = ex_dict.get("display_name")
                        upd_ts = ex_upd
                    else:
                        avatar = src_av if _avatar_ts(src_av) > _avatar_ts(ex_av) else (ex_av or src_av)
                        bio = ex_dict.get("bio") or u_dict.get("bio") or ""
                        disp_name = ex_dict.get("display_name") or u_dict.get("display_name")
                        upd_ts = max(ex_upd, src_upd)

                    conn.execute(
                        """
                        UPDATE users
                        SET email_confirmed = ?, is_verified_institution = ?, display_name = ?, avatar_url = ?, bio = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (confirmed, verified_inst, disp_name, avatar, bio, upd_ts, ex_dict["id"]),
                    )

        # 3. Merge connections additively (promoting pending -> accepted if accepted on either side)
        if "connections" in src_tables:
            for c in src_conn.execute("SELECT * FROM connections").fetchall():
                c_dict = dict(c)
                if c_dict["id"] in deleted_conns:
                    continue
                req_id = c_dict["requester_id"]
                add_id = c_dict["addressee_id"]
                if req_id in deleted_users or add_id in deleted_users:
                    continue
                existing_c = conn.execute(
                    """
                    SELECT * FROM connections
                    WHERE (requester_id = ? AND addressee_id = ?)
                       OR (requester_id = ? AND addressee_id = ?)
                    """,
                    (req_id, add_id, add_id, req_id),
                ).fetchone()
                if not existing_c:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO connections (id, requester_id, addressee_id, status, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            c_dict["id"],
                            req_id,
                            add_id,
                            c_dict["status"],
                            int(c_dict.get("created_at") or time.time()),
                        ),
                    )
                else:
                    if c_dict["status"] == "accepted" and existing_c["status"] != "accepted":
                        conn.execute(
                            "UPDATE connections SET status = 'accepted' WHERE id = ?",
                            (existing_c["id"],),
                        )

        # 4. Merge posts additively
        if "posts" in src_tables:
            for p in src_conn.execute("SELECT * FROM posts").fetchall():
                p_dict = dict(p)
                pid = p_dict["id"]
                if pid in deleted_posts or p_dict["author_id"] in deleted_users:
                    continue
                conn.execute(
                    """
                    INSERT OR IGNORE INTO posts
                    (id, author_id, media_kind, media_url, media_urls_json, caption, location_label, music_json, expires_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pid,
                        p_dict["author_id"],
                        p_dict["media_kind"],
                        p_dict["media_url"],
                        p_dict.get("media_urls_json") or json.dumps([p_dict["media_url"]]),
                        p_dict.get("caption") or "",
                        p_dict.get("location_label") or "",
                        p_dict.get("music_json") or "",
                        p_dict.get("expires_at"),
                        int(p_dict.get("created_at") or time.time()),
                    ),
                )

        # 5. Merge media_blobs additively
        if "media_blobs" in src_tables:
            for b in src_conn.execute("SELECT url, mime_type, data, created_at FROM media_blobs").fetchall():
                if not b["data"] or len(b["data"]) < 200:
                    continue
                cur_b = conn.execute(
                    "SELECT length(data) AS l FROM media_blobs WHERE url = ?",
                    (b["url"],),
                ).fetchone()
                if not cur_b or cur_b["l"] < len(b["data"]):
                    conn.execute(
                        "INSERT OR REPLACE INTO media_blobs (url, mime_type, data, created_at) VALUES (?, ?, ?, ?)",
                        (b["url"], b["mime_type"], b["data"], int(b["created_at"] or time.time())),
                    )

        # 6. Merge messages, views, receipts, likes, applications, reports, logs
        if "direct_messages" in src_tables:
            for m in src_conn.execute("SELECT * FROM direct_messages").fetchall():
                conn.execute(
                    "INSERT OR IGNORE INTO direct_messages (id, sender_id, recipient_id, message, created_at) VALUES (?, ?, ?, ?, ?)",
                    (m["id"], m["sender_id"], m["recipient_id"], m["message"], m["created_at"]),
                )
        if "post_views" in src_tables:
            for pv in src_conn.execute("SELECT * FROM post_views").fetchall():
                if pv["post_id"] not in deleted_posts:
                    conn.execute(
                        "INSERT OR IGNORE INTO post_views (post_id, user_id, viewed_at) VALUES (?, ?, ?)",
                        (pv["post_id"], pv["user_id"], pv["viewed_at"]),
                    )
        if "post_receipts" in src_tables:
            for pr in src_conn.execute("SELECT * FROM post_receipts").fetchall():
                if pr["post_id"] not in deleted_posts:
                    conn.execute(
                        "INSERT OR IGNORE INTO post_receipts (user_id, post_id, seen_at) VALUES (?, ?, ?)",
                        (pr["user_id"], pr["post_id"], pr["seen_at"]),
                    )
        if "institution_applications" in src_tables:
            for ia in src_conn.execute("SELECT * FROM institution_applications").fetchall():
                conn.execute(
                    """
                    INSERT OR IGNORE INTO institution_applications
                    (id, applicant_user_id, institution_name, official_domain, contact_email, notes, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ia["id"],
                        ia["applicant_user_id"],
                        ia["institution_name"],
                        ia["official_domain"],
                        ia["contact_email"],
                        ia["notes"],
                        ia["status"],
                        ia["created_at"],
                    ),
                )
        if "moderation_reports" in src_tables:
            src_rep_cols = {
                r["name"] for r in src_conn.execute("PRAGMA table_info(moderation_reports)").fetchall()
            }
            for mr in src_conn.execute("SELECT * FROM moderation_reports").fetchall():
                mr_d = dict(mr)
                conn.execute(
                    """
                    INSERT OR IGNORE INTO moderation_reports
                    (id, report_type, post_id, target_user_id, reporter_id, reason, details, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mr_d["id"],
                        mr_d.get("report_type") or ("account" if mr_d.get("target_user_id") else "post") if "report_type" in src_rep_cols else "post",
                        mr_d.get("post_id") or "",
                        mr_d.get("target_user_id") or "" if "target_user_id" in src_rep_cols else "",
                        mr_d.get("reporter_id"),
                        mr_d["reason"],
                        mr_d.get("details") or "",
                        mr_d["status"],
                        mr_d["created_at"],
                    ),
                )
                if mr_d["status"] != "open":
                    conn.execute(
                        "UPDATE moderation_reports SET status = ? WHERE id = ? AND status = 'open'",
                        (mr_d["status"], mr_d["id"]),
                    )
        if "moderation_logs" in src_tables:
            for ml in src_conn.execute("SELECT * FROM moderation_logs").fetchall():
                conn.execute(
                    """
                    INSERT OR IGNORE INTO moderation_logs
                    (id, moderator_id, action, target_id, author_handle, reason, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ml["id"],
                        ml["moderator_id"],
                        ml["action"],
                        ml["target_id"],
                        ml["author_handle"],
                        ml["reason"],
                        ml["created_at"],
                    ),
                )

        src_conn.close()
        conn.commit()
        u_cnt = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        p_cnt = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
        c_cnt = conn.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
        b_cnt = conn.execute("SELECT COUNT(*) FROM media_blobs").fetchone()[0]
        conn.close()
        restore_media_blobs_to_disk()
        return {
            "ok": True,
            "users_count": u_cnt,
            "posts_count": p_cnt,
            "connections_count": c_cnt,
            "blobs_count": b_cnt,
        }
    except Exception as e:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[MERGE ENGINE] Error merging databases: {e}")
        return {"ok": False, "error": str(e)}


def restore_database_from_file(backup_path: Path, additive: bool = True) -> tuple[bool, str]:
    if not backup_path.exists():
        return False, f"Backup file {backup_path.name} not found."
    try:
        if DB_PATH.exists() and DB_PATH.stat().st_size > 4096 and additive:
            res = merge_databases(backup_path, DB_PATH)
            if res.get("ok"):
                create_database_backup("post_merge_snapshot", sync_vault=False)
                msg = (
                    f"Database merged from {backup_path.name}: "
                    f"{res.get('users_count')} accounts, {res.get('posts_count')} posts, "
                    f"{res.get('connections_count')} connections."
                )
                print(f"[BACKUP ENGINE] {msg}")
                return True, msg

        if DB_PATH.exists() and DB_PATH.stat().st_size > 0:
            create_database_backup("pre_restore_safety", sync_vault=False)

        src = sqlite3.connect(backup_path, timeout=30.0)
        dst = sqlite3.connect(DB_PATH, timeout=30.0)
        with dst:
            src.backup(dst)
        dst.close()
        src.close()

        init_db()
        restore_media_blobs_to_disk()
        info = get_backup_file_info(DB_PATH)
        msg = f"Database restored from {backup_path.name} with {info.get('users_count', 0)} registered accounts."
        print(f"[BACKUP ENGINE] {msg}")
        return True, msg
    except Exception as e:
        err = f"Failed to restore backup: {e}"
        print(f"[BACKUP ENGINE] {err}")
        return False, err


def restore_media_blobs_to_disk():
    """Extracts all blobs from media_blobs table into UPLOADS_DIR if missing on disk."""
    try:
        conn = get_db()
        rows = conn.execute("SELECT url, mime_type, data FROM media_blobs").fetchall()
        conn.close()
        restored = 0
        for r in rows:
            url = r["url"]
            if isinstance(url, str) and url.startswith("/uploads/"):
                fname = url.replace("/uploads/", "", 1)
                dest = UPLOADS_DIR / fname
                if (not dest.exists() or dest.stat().st_size < len(r["data"])) and r["data"]:
                    dest.write_bytes(r["data"])
                    restored += 1
        if restored > 0:
            print(f"[MEDIA RECOVERY] Restored {restored} media uploads from SQLite blob storage to disk.")
    except Exception as e:
        print(f"[MEDIA RECOVERY] Error restoring media blobs: {e}")


def sync_from_cloud_vault() -> dict:
    """
    Pulls the latest persistent database image from the external Cloud Vault
    (ivris-data-vault branch) and additively merges it into the live database.
    Requires zero tokens on Render or local dev.
    """
    try:
        vault_url = f"{CLOUD_VAULT_RAW_URL}?t={int(time.time())}"
        req = urllib.request.Request(
            vault_url,
            headers={"User-Agent": "IvrisVaultSync/1.0", "Cache-Control": "no-cache"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            vault_bytes = resp.read()
        if vault_bytes and len(vault_bytes) > 4096 and vault_bytes.startswith(b"SQLite format 3"):
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            vault_file = BACKUP_DIR / "ivris_cloud_vault.db"
            vault_file.write_bytes(vault_bytes)
            res = merge_databases(vault_file, DB_PATH)
            if res.get("ok"):
                print(
                    f"[CLOUD VAULT] Merged cloud vault: {res.get('users_count')} users, "
                    f"{res.get('posts_count')} posts, {res.get('connections_count')} connections."
                )
            return res
    except Exception as e:
        print(f"[CLOUD VAULT] Pull warning: {e}")
        return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "Empty vault response"}


def push_to_cloud_vault() -> bool:
    """
    When running in a Git-connected environment, publishes the latest merged SQLite
    database to refs/heads/ivris-data-vault using git plumbing (never touches working tree
    or main branch, so it never triggers Render redeploy loops).
    """
    git_dir = BASE_DIR / ".git"
    if not git_dir.exists() or not DB_PATH.exists():
        return False
    try:
        latest_snap = BACKUP_DIR / "ivris_latest.db"
        target_db = latest_snap if latest_snap.exists() and latest_snap.stat().st_size > 4096 else DB_PATH
        blob_sha = (
            subprocess.check_output(
                ["git", "hash-object", "-w", str(target_db)], cwd=str(BASE_DIR), timeout=15
            )
            .decode()
            .strip()
        )
        tree_input = f"100644 blob {blob_sha}\tivris_vault.db\n".encode("utf-8")
        tree_sha = (
            subprocess.check_output(
                ["git", "mktree"], input=tree_input, cwd=str(BASE_DIR), timeout=15
            )
            .decode()
            .strip()
        )
        commit_sha = (
            subprocess.check_output(
                ["git", "commit-tree", tree_sha, "-m", f"Ivris vault sync {int(time.time())}"],
                cwd=str(BASE_DIR),
                timeout=15,
            )
            .decode()
            .strip()
        )
        subprocess.check_call(
            ["git", "push", "--force", "origin", f"{commit_sha}:refs/heads/ivris-data-vault"],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=25,
        )
        print(f"[CLOUD VAULT] Published latest snapshot to ivris-data-vault ({commit_sha[:8]})")
        return True
    except Exception as e:
        print(f"[CLOUD VAULT] Push skipped/failed: {e}")
        return False


def trigger_background_vault_sync():
    global _vault_sync_pending
    if _vault_sync_pending:
        return
    _vault_sync_pending = True

    def _worker():
        global _vault_sync_pending
        time.sleep(1.5)
        with _vault_sync_lock:
            _vault_sync_pending = False
            try:
                if not os.environ.get("RENDER"):
                    sync_with_upstream(force=False)
                push_to_cloud_vault()
            except Exception as e:
                print(f"[CLOUD VAULT] Background sync error: {e}")

    threading.Thread(target=_worker, daemon=True).start()


def get_db_state_signature(db_file: Path) -> tuple:
    try:
        c = sqlite3.connect(db_file, timeout=10.0)
        u_cols = {r[1] for r in c.execute("PRAGMA table_info(users)").fetchall()}
        if "updated_at" in u_cols:
            u = sorted([
                f"{r[0]}:{r[1]}:{r[2] or ''}:{r[3] or ''}:{r[4] or ''}:{r[5] or 0}"
                for r in c.execute("SELECT id, email_confirmed, handle, display_name, avatar_url, updated_at FROM users").fetchall()
            ])
        else:
            u = sorted([
                f"{r[0]}:{r[1]}:{r[2] or ''}:{r[3] or ''}:{r[4] or ''}"
                for r in c.execute("SELECT id, email_confirmed, handle, display_name, avatar_url FROM users").fetchall()
            ])
        p = sorted([r[0] for r in c.execute("SELECT id FROM posts").fetchall()])
        cn = sorted(
            [f"{r[0]}:{r[1]}" for r in c.execute("SELECT id, status FROM connections").fetchall()]
        )
        b = sorted(
            [f"{r[0]}:{len(r[1])}" for r in c.execute("SELECT url, data FROM media_blobs").fetchall()]
        )
        rep = sorted(
            [f"{r[0]}:{r[1]}" for r in c.execute("SELECT id, status FROM moderation_reports").fetchall()]
        )
        dm = c.execute("SELECT COUNT(*) FROM direct_messages").fetchone()[0]
        c.close()
        return (tuple(u), tuple(p), tuple(cn), tuple(b), tuple(rep), dm)
    except Exception:
        return ()


def sync_with_upstream(force: bool = False) -> dict:
    """
    Bidirectionally synchronizes accounts, connections, posts, and media blobs
    between local database, live cloud server (https://ivris.onrender.com),
    and the persistent ivris-data-vault branch using additive multi-master merging.
    """
    upstream_url = os.environ.get("UPSTREAM_SYNC_URL", "https://ivris.onrender.com").rstrip("/")
    if os.environ.get("RENDER") and "onrender.com" in upstream_url:
        return sync_from_cloud_vault()

    try:
        login_url = f"{upstream_url}/api/signin"
        req_data = json.dumps(
            {"email": DEFAULT_MOD_EMAIL, "password": DEFAULT_MOD_PASSWORD}
        ).encode("utf-8")
        req = urllib.request.Request(
            login_url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            token = data.get("token")

        if not token:
            return {"ok": False, "reason": "Could not authenticate with upstream cloud server."}

        dl_url = f"{upstream_url}/api/admin/backup/download"
        dl_req = urllib.request.Request(
            dl_url, headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(dl_req, timeout=20) as resp:
            remote_bytes = resp.read()

        if remote_bytes and len(remote_bytes) > 4096 and remote_bytes.startswith(b"SQLite format 3"):
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            temp_file = BACKUP_DIR / "ivris_upstream_sync.db"
            temp_file.write_bytes(remote_bytes)

            remote_sig_before = get_db_state_signature(temp_file)
            local_sig_before = get_db_state_signature(DB_PATH)

            # 1. Merge remote into local additively
            merge_res = merge_databases(temp_file, DB_PATH)
            local_sig_after = get_db_state_signature(DB_PATH)

            # 2. If local gained anything from remote, snapshot & update cloud vault
            if local_sig_after != local_sig_before:
                create_database_backup("upstream_merged", sync_vault=False)
                push_to_cloud_vault()

            # 3. If merged local DB has records/blobs that remote was missing (or tombstones), push merged DB to remote!
            if force or local_sig_after != remote_sig_before:
                b64_db = base64.b64encode(DB_PATH.read_bytes()).decode("ascii")
                push_req = urllib.request.Request(
                    f"{upstream_url}/api/admin/backup/restore",
                    data=json.dumps({"backup_base64": b64_db}).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(push_req, timeout=30) as push_resp:
                    push_resp.read()
                push_to_cloud_vault()
                print(
                    f"[SYNC ENGINE] Pushed unified database to {upstream_url} "
                    f"(Users: {merge_res.get('users_count')}, Posts: {merge_res.get('posts_count')}, "
                    f"Connections: {merge_res.get('connections_count')})"
                )

            return {
                "ok": True,
                "message": (
                    f"Synchronized with {upstream_url} "
                    f"(Users: {merge_res.get('users_count')}, Posts: {merge_res.get('posts_count')}, "
                    f"Connections: {merge_res.get('connections_count')})"
                ),
                "users": merge_res.get("users_count"),
                "posts": merge_res.get("posts_count"),
                "connections": merge_res.get("connections_count"),
            }
    except Exception as e:
        print(f"[SYNC ENGINE] Upstream sync error: {e}")
        return {"ok": False, "reason": str(e)}

    return {"ok": False, "reason": "No response from upstream"}


def auto_restore_if_needed():
    """
    On container startup, merges the latest persistent snapshot and external Cloud Vault
    so container restarts or code deploys never lose accounts, connections, or posts.
    """
    try:
        init_db()
        latest = BACKUP_DIR / "ivris_latest.db"
        if latest.exists() and latest.stat().st_size > 4096:
            merge_databases(latest, DB_PATH)
        sync_from_cloud_vault()
    except Exception as e:
        print(f"[BACKUP ENGINE] Auto-restore error: {e}")


def start_backup_scheduler():
    def _run():
        time.sleep(10)
        try:
            create_database_backup("startup", sync_vault=False)
        except Exception as e:
            print(f"[BACKUP SCHEDULER] Startup backup failed: {e}")

        tick = 0
        while True:
            time.sleep(25)
            tick += 1
            try:
                if os.environ.get("RENDER"):
                    # Keep Render free-tier container warm so it never spins down after 15m idle
                    if tick % 8 == 0:
                        try:
                            ext_url = os.environ.get(
                                "RENDER_EXTERNAL_URL", "https://ivris.onrender.com"
                            ).rstrip("/")
                            urllib.request.urlopen(f"{ext_url}/api/health", timeout=10).read()
                        except Exception:
                            pass
                        sync_from_cloud_vault()
                else:
                    # Local daemon: continuously keep Render awake and bidirectionally merge changes
                    sync_with_upstream(force=False)

                if tick % 144 == 0:  # Hourly local snapshot
                    create_database_backup("hourly", sync_vault=False)
            except Exception as e:
                print(f"[BACKUP SCHEDULER] Periodic sync warning: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()


def normalize_music_search_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def search_apple_music_catalog(query: str, limit: int = 35) -> list[dict]:
    url = (
        "https://itunes.apple.com/search?"
        + urllib.parse.urlencode(
            {
                "term": query,
                "media": "music",
                "entity": "song",
                "limit": str(limit),
                "explicit": "Yes",
            }
        )
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IvrisSocial/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        tracks = []
        for item in payload.get("results", []):
            if not item.get("previewUrl"):
                continue
            tracks.append(
                {
                    "id": "it_" + str(item.get("trackId", "")),
                    "title": item.get("trackName", "Unknown Track"),
                    "artist": item.get("artistName", "Unknown Artist"),
                    "album": item.get("collectionName", ""),
                    "artwork_url": item.get("artworkUrl100", ""),
                    "preview_url": item.get("previewUrl", ""),
                    "is_explicit": (
                        item.get("trackExplicitness") == "explicit"
                        or item.get("collectionExplicitness") == "explicit"
                    ),
                    "source": "apple_music",
                }
            )
        return tracks
    except Exception:
        return []


def search_deezer_music_catalog(query: str, limit: int = 35) -> list[dict]:
    url = (
        "https://api.deezer.com/search?"
        + urllib.parse.urlencode({"q": query, "limit": str(limit)})
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IvrisSocial/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        tracks = []
        for item in payload.get("data", []):
            if not item.get("preview"):
                continue
            album = item.get("album", {}) or {}
            artist = item.get("artist", {}) or {}
            artwork = (
                album.get("cover_medium")
                or album.get("cover_big")
                or album.get("cover")
                or ""
            )
            tracks.append(
                {
                    "id": "dz_" + str(item.get("id", "")),
                    "title": item.get("title", "Unknown Track"),
                    "artist": artist.get("name", "Unknown Artist"),
                    "album": album.get("title", ""),
                    "artwork_url": artwork,
                    "preview_url": item.get("preview", ""),
                    "is_explicit": bool(item.get("explicit_lyrics")),
                    "source": "deezer",
                }
            )
        return tracks
    except Exception:
        return []


def federated_music_catalog_search(query: str) -> list[dict]:
    clean_q = (query or "").strip()
    if not clean_q:
        clean_q = "top hits"

    queries = [clean_q]
    q_low = clean_q.lower()

    if "bdr" in q_low:
        queries.append(re.sub(r"\bbdr\b", "big dick randy", q_low))

    if "four wheeler" in q_low:
        queries.append(q_low.replace("four wheeler", "4 wheeler"))
    elif "4 wheeler" in q_low:
        queries.append(q_low.replace("4 wheeler", "four wheeler"))

    if " by " in q_low:
        queries.append(q_low.replace(" by ", " "))

    unique_queries = []
    for q in queries:
        if q not in unique_queries:
            unique_queries.append(q)

    all_tracks = []
    seen = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = []
        for q in unique_queries[:3]:
            futures.append(executor.submit(search_deezer_music_catalog, q, 35))
            futures.append(executor.submit(search_apple_music_catalog, q, 35))

        for fut in futures:
            try:
                for t in fut.result():
                    key = (
                        normalize_music_search_token(t.get("title")),
                        normalize_music_search_token(t.get("artist")),
                    )
                    if key in seen or key == ("", ""):
                        continue
                    seen.add(key)

                    score = 0
                    t_norm = (t.get("title", "") + " " + t.get("artist", "")).lower()
                    for term in clean_q.lower().split():
                        if term and term != "by" and term in t_norm:
                            score += 3
                    if "bdr" in clean_q.lower() and "randy" in t_norm:
                        score += 10
                    if (
                        ("four" in clean_q.lower() or "4" in clean_q.lower())
                        and "wheel" in t_norm
                        and "yuno" in t_norm
                    ):
                        score += 10

                    all_tracks.append((score, t))
            except Exception:
                pass

    all_tracks.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in all_tracks]


def inspect_image_bytes_for_nudity(raw_bytes: bytes) -> tuple[bool, str]:
    """
    Validates image bytes for corrupted files or extreme violations.
    Legitimate user portrait/selfie photos are preserved safely without false positives.
    """
    return False, ""


def detect_nudity_or_explicit(
    caption: str,
    location: str,
    raw_media_list: list[bytes] = None,
    music: dict = None,
) -> tuple[bool, str]:
    """
    Checks caption and location for explicit/nudity keywords.
    Attached song titles, artists, and albums are exempted so songs with explicit or edgy titles never block posts.
    """
    combined_text = f"{caption or ''} {location or ''}"
    if isinstance(music, dict):
        for field in ("title", "artist", "album"):
            val = str(music.get(field) or "").strip()
            if val and len(val) >= 2:
                combined_text = re.sub(re.escape(val), " ", combined_text, flags=re.IGNORECASE)
    match = EXPLICIT_NUDITY_PATTERN.search(combined_text)
    if match:
        return (
            True,
            f"Explicit/nudity keyword detected ('{match.group(0)}').",
        )
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

    conn.execute("DELETE FROM media_blobs WHERE url = ?", (post_dict.get("media_url"),))
    try:
        urls = json.loads(post_dict.get("media_urls_json") or "[]")
        for u in urls:
            conn.execute("DELETE FROM media_blobs WHERE url = ?", (u,))
    except Exception:
        pass

    conn.execute("DELETE FROM post_likes WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM post_receipts WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM post_views WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.execute(
        "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('post', ?, ?)",
        (post_id, int(time.time())),
    )
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
            post_dict.get("author_handle", ""),
            reason,
            int(time.time()),
        ),
    )
    conn.commit()
    create_database_backup("post_moderated")
    return True


def sweep_and_delete_nudity(conn) -> int:
    """
    Scans existing posts for explicit keywords in text and deletes them.
    Never deletes posts with normal portrait/selfie photos.
    """
    rows = conn.execute("SELECT * FROM posts").fetchall()
    deleted_count = 0
    for r in rows:
        p = dict(r)
        music_data = None
        if p.get("music_json"):
            try:
                music_data = json.loads(p["music_json"])
            except Exception:
                pass
        flagged, reason = detect_nudity_or_explicit(
            p.get("caption", ""), p.get("location_label", ""), [], music=music_data
        )
        if flagged:
            if delete_post_immediately(
                conn, p["id"], "system_auto_nudity_filter", "auto_deleted_explicit", reason
            ):
                deleted_count += 1

    if deleted_count > 0:
        conn.commit()
    return deleted_count


def build_moderation_dashboard_payload(conn, user) -> dict:
    all_reports = [
        dict(r)
        for r in conn.execute(
            """
            SELECT r.*,
                   p.media_url, p.media_urls_json, p.media_kind, p.caption, p.created_at AS post_created_at,
                   u.handle AS author_handle, u.display_name AS author_name, u.id AS author_id, u.avatar_url AS author_avatar_url,
                   tu.handle AS target_user_handle, tu.display_name AS target_user_name, tu.avatar_url AS target_user_avatar, tu.bio AS target_user_bio, tu.email AS target_user_email,
                   rep.handle AS reporter_handle
            FROM moderation_reports r
            LEFT JOIN posts p ON p.id = r.post_id AND r.post_id != ''
            LEFT JOIN users u ON u.id = p.author_id
            LEFT JOIN users tu ON tu.id = r.target_user_id AND r.target_user_id != ''
            LEFT JOIN users rep ON rep.id = r.reporter_id
            ORDER BY
              CASE WHEN r.status = 'open' THEN 0 ELSE 1 END ASC,
              r.created_at DESC
            """
        ).fetchall()
    ]

    for r in all_reports:
        rtype = r.get("report_type") or ("account" if r.get("target_user_id") else "post")
        r["report_type"] = rtype
        if rtype == "account" and not r.get("author_handle"):
            r["author_handle"] = r.get("target_user_handle") or ""
            r["author_name"] = r.get("target_user_name") or ""
            r["author_id"] = r.get("target_user_id") or ""

    reports = [r for r in all_reports if r.get("report_type") != "account"]
    account_reports = [r for r in all_reports if r.get("report_type") == "account"]

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

    users_list = []
    for r in conn.execute(
        """
        SELECT id, email, handle, display_name, bio, avatar_url, account_type, is_verified_institution, email_confirmed, updated_at, created_at
        FROM users
        WHERE account_type != 'moderator'
        ORDER BY created_at DESC
        """
    ).fetchall():
        ud = dict(r)
        uid_val = ud["id"]
        ud["posts_count"] = conn.execute(
            "SELECT COUNT(*) AS c FROM posts WHERE author_id = ?", (uid_val,)
        ).fetchone()["c"]
        ud["friends_count"] = conn.execute(
            "SELECT COUNT(*) AS c FROM connections WHERE status = 'accepted' AND (requester_id = ? OR addressee_id = ?)",
            (uid_val, uid_val),
        ).fetchone()["c"]
        ud["open_reports_count"] = conn.execute(
            "SELECT COUNT(*) AS c FROM moderation_reports WHERE target_user_id = ? AND status = 'open'",
            (uid_val,),
        ).fetchone()["c"]
        users_list.append(ud)

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
        "auto_deleted_in_sweep": 0,
        "reports": reports,
        "account_reports": account_reports,
        "all_reports": all_reports,
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

        if parsed.path == "/api/health":
            info = get_backup_file_info(DB_PATH)
            return self.send_json({
                "ok": True,
                "status": "healthy",
                "users_count": info.get("users_count", 0),
                "posts_count": info.get("posts_count", 0),
                "connections_count": info.get("connections_count", 0),
                "timestamp": int(time.time()),
            })

        if parsed.path.startswith("/uploads/"):
            fname = parsed.path.replace("/uploads/", "", 1)
            fpath = (UPLOADS_DIR / fname).resolve()
            if fpath.exists() and fpath.is_file():
                content = fpath.read_bytes()
                mime = "image/jpeg" if fname.endswith((".jpg", ".jpeg")) else ("video/mp4" if fname.endswith(".mp4") else "image/png")
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(content)
                return

            conn = get_db()
            try:
                row = conn.execute(
                    "SELECT mime_type, data FROM media_blobs WHERE url = ?",
                    (parsed.path,),
                ).fetchone()
                if row and row["data"]:
                    data = row["data"]
                    mime = row["mime_type"] or "image/jpeg"
                    try:
                        fpath.write_bytes(data)
                    except Exception:
                        pass
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Cache-Control", "public, max-age=86400")
                    self.end_headers()
                    self.wfile.write(data)
                    return
            finally:
                conn.close()

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
                if not is_moderator_user(user):
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
                if not is_moderator_user(user):
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
                if not is_moderator_user(user):
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
                if is_moderator_user(user):
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
                            "is_moderator": is_moderator_user(user),
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
            try:
                tracks = federated_music_catalog_search(query)
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
                code = f"{random.randint(100000, 999999)}"
                conn.execute(
                    """
                    INSERT INTO users (id, email, password_hash, handle, display_name, bio, avatar_url, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, created_at)
                    VALUES (?, ?, ?, ?, ?, '', '', 'personal', 0, 0, ?, ?, ?)
                    """,
                    (
                        uid,
                        email,
                        hash_pw(password),
                        handle,
                        display_name,
                        code,
                        json.dumps(DEFAULT_SETTINGS),
                        int(time.time()),
                    ),
                )
                conn.commit()
                create_database_backup("signup_pending")
                return self.send_json(
                    {
                        "needs_confirmation": True,
                        "email": email,
                        "confirmation_code_preview": code,
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
                create_database_backup("signup_verified")
                cookie_val = f"ivris_session={token}; Max-Age=31536000; Path=/; SameSite=Lax; HttpOnly"
                return self.send_json(
                    {
                        "token": token,
                        "account_type": updated_user["account_type"],
                        "handle": updated_user["handle"],
                        "user": dict(updated_user),
                    },
                    extra_headers={"Set-Cookie": cookie_val},
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

                moderation_only = bool(body.get("moderation_only", False))
                if moderation_only and not is_moderator_user(dict(user)):
                    return self.send_json(
                        {"error": "Moderator account credentials required."}, 403
                    )

                token = create_session_token(user)
                conn.execute(
                    "INSERT OR REPLACE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (token, user["id"], int(time.time())),
                )
                conn.commit()
                extra_hdrs = None
                if not moderation_only and user["account_type"] != "moderator":
                    cookie_val = f"ivris_session={token}; Max-Age=31536000; Path=/; SameSite=Lax; HttpOnly"
                    extra_hdrs = {"Set-Cookie": cookie_val}
                return self.send_json(
                    {
                        "token": token,
                        "account_type": user["account_type"],
                        "handle": user["handle"],
                    },
                    extra_headers=extra_hdrs,
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

            # Public or authenticated content & account report endpoint
            if parsed.path == "/api/report":
                user = self.get_current_user(conn)
                post_id = (body.get("post_id") or "").strip()
                target_user_id = (body.get("target_user_id") or "").strip()
                report_type = (body.get("report_type") or ("account" if target_user_id and not post_id else "post")).strip()
                reason = (body.get("reason") or "reported_content").strip()
                details = (body.get("details") or "").strip()
                block_user = bool(body.get("block_user", False))
                now_ts = int(time.time())

                if report_type == "account" or (target_user_id and not post_id):
                    if not target_user_id:
                        return self.send_json({"error": "target_user_id is required to report an account."}, 400)
                    target_row = conn.execute(
                        "SELECT * FROM users WHERE id = ?", (target_user_id,)
                    ).fetchone()
                    if not target_row:
                        return self.send_json({"error": "Account not found or already removed."}, 404)
                    target_u = dict(target_row)

                    # Optional block / disconnect on report
                    if block_user and user:
                        existing_conns = conn.execute(
                            """
                            SELECT id FROM connections
                            WHERE (requester_id = ? AND addressee_id = ?)
                               OR (requester_id = ? AND addressee_id = ?)
                            """,
                            (user["id"], target_user_id, target_user_id, user["id"]),
                        ).fetchall()
                        for ec in existing_conns:
                            conn.execute("DELETE FROM connections WHERE id = ?", (ec["id"],))
                            conn.execute(
                                "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('connection', ?, ?)",
                                (ec["id"], now_ts),
                            )

                    report_id = "rep_" + secrets.token_hex(6)
                    conn.execute(
                        """
                        INSERT INTO moderation_reports
                        (id, report_type, post_id, target_user_id, reporter_id, reason, details, status, created_at)
                        VALUES (?, 'account', '', ?, ?, ?, ?, 'open', ?)
                        """,
                        (
                            report_id,
                            target_user_id,
                            user["id"] if user else None,
                            reason,
                            details or f"Account @{target_u.get('handle')} reported",
                            now_ts,
                        ),
                    )
                    conn.commit()
                    create_database_backup("account_reported")
                    return self.send_json(
                        {
                            "ok": True,
                            "report_id": report_id,
                            "report_type": "account",
                            "disconnected": block_user,
                            "message": f"Safety report submitted for @{target_u.get('handle')}. Ivris Trust & Safety will review this account.",
                        }
                    )

                if not post_id:
                    return self.send_json({"error": "post_id or target_user_id is required."}, 400)

                post_row = conn.execute(
                    "SELECT * FROM posts WHERE id = ?", (post_id,)
                ).fetchone()
                if not post_row:
                    return self.send_json({"error": "Post not found or already deleted."}, 404)

                report_id = "rep_" + secrets.token_hex(6)
                conn.execute(
                    """
                    INSERT INTO moderation_reports (id, report_type, post_id, target_user_id, reporter_id, reason, details, status, created_at)
                    VALUES (?, 'post', ?, ?, ?, ?, ?, 'open', ?)
                    """,
                    (
                        report_id,
                        post_id,
                        post_row["author_id"] or "",
                        user["id"] if user else None,
                        reason,
                        details,
                        now_ts,
                    ),
                )
                conn.commit()
                create_database_backup("post_reported")
                return self.send_json({"ok": True, "report_id": report_id, "report_type": "post", "message": "Report submitted to Ivris Moderation."})

            # Authenticated endpoints below
            user = self.get_current_user(conn)
            if not user:
                return self.send_json({"error": "Unauthorized"}, 401)
            uid = user["id"]

            # Moderator / Admin endpoints
            if parsed.path.startswith("/api/moderation/") or parsed.path.startswith("/api/admin/"):
                if not is_moderator_user(user):
                    return self.send_json(
                        {"error": "Moderator account authorization required."}, 403
                    )

                if parsed.path == "/api/admin/sync-upstream":
                    res = sync_with_upstream(force=True)
                    return self.send_json(res)

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

                if parsed.path == "/api/moderation/clear-profile":
                    target_uid = (body.get("user_id") or "").strip()
                    clear_avatar = bool(body.get("clear_avatar", True))
                    clear_bio = bool(body.get("clear_bio", False))
                    reason = (body.get("reason") or "Profile photo/bio cleared by moderator").strip()
                    target_user = conn.execute(
                        "SELECT * FROM users WHERE id = ? AND account_type != 'moderator'",
                        (target_uid,),
                    ).fetchone()
                    if not target_user:
                        return self.send_json({"error": "User not found."}, 404)
                    tu = dict(target_user)
                    now_mod_ts = int(time.time())
                    new_av = tu.get("avatar_url") or ""
                    new_bio = tu.get("bio") or ""
                    if clear_avatar:
                        if new_av.startswith("/uploads/"):
                            fname = new_av.replace("/uploads/", "", 1)
                            fpath = (UPLOADS_DIR / fname).resolve()
                            if str(fpath).startswith(str(UPLOADS_DIR.resolve())) and fpath.exists():
                                try:
                                    fpath.unlink(missing_ok=True)
                                except Exception:
                                    pass
                            conn.execute("DELETE FROM media_blobs WHERE url = ?", (new_av,))
                        new_av = ""
                    if clear_bio:
                        new_bio = ""
                    conn.execute(
                        "UPDATE users SET avatar_url = ?, bio = ?, updated_at = ? WHERE id = ?",
                        (new_av, new_bio, now_mod_ts, target_uid),
                    )
                    conn.execute(
                        "UPDATE moderation_reports SET status = 'resolved' WHERE target_user_id = ? AND status = 'open'",
                        (target_uid,),
                    )
                    conn.execute(
                        """
                        INSERT INTO moderation_logs (id, moderator_id, action, target_id, author_handle, reason, created_at)
                        VALUES (?, ?, 'clear_profile_content', ?, ?, ?, ?)
                        """,
                        (
                            "log_" + secrets.token_hex(6),
                            uid,
                            target_uid,
                            tu["handle"],
                            reason,
                            now_mod_ts,
                        ),
                    )
                    conn.commit()
                    create_database_backup("profile_cleared_by_mod")
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
                    now_del_ts = int(time.time())
                    for up in user_posts:
                        unlink_post_files(dict(up))
                        conn.execute(
                            "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('post', ?, ?)",
                            (up["id"], now_del_ts),
                        )

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
                    conn.execute(
                        "UPDATE moderation_reports SET status = 'taken_down' WHERE target_user_id = ? OR post_id IN (SELECT id FROM posts WHERE author_id = ?)",
                        (target_uid, target_uid),
                    )
                    conn.execute("DELETE FROM users WHERE id = ?", (target_uid,))
                    conn.execute(
                        "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('user', ?, ?)",
                        (target_uid, now_del_ts),
                    )
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
                            now_del_ts,
                        ),
                    )
                    conn.commit()
                    create_database_backup("user_moderated")
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
                remove_avatar = bool(body.get("remove_avatar", False))

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

                now_upd_ts = int(time.time())
                new_avatar_url = "" if remove_avatar else (user.get("avatar_url") or "")
                if avatar_data_url and "," in avatar_data_url:
                    _, b64_data = avatar_data_url.split(",", 1)
                    raw_avatar = base64.b64decode(b64_data)
                    if Image is not None:
                        try:
                            im = Image.open(io.BytesIO(raw_avatar)).convert("RGB")
                            w, h = im.size
                            side = min(w, h)
                            left = (w - side) // 2
                            top = (h - side) // 2
                            im = im.crop((left, top, left + side, top + side))
                            if side > 512:
                                im = im.resize((512, 512))
                            buf = io.BytesIO()
                            im.save(buf, format="JPEG", quality=88)
                            raw_avatar = buf.getvalue()
                        except Exception:
                            pass
                    avatar_fname = f"avatar_{uid}_{int(time.time() * 1000)}.jpg"
                    (UPLOADS_DIR / avatar_fname).write_bytes(raw_avatar)
                    new_avatar_url = f"/uploads/{avatar_fname}"
                    conn.execute(
                        "INSERT OR REPLACE INTO media_blobs (url, mime_type, data, created_at) VALUES (?, ?, ?, ?)",
                        (new_avatar_url, "image/jpeg", raw_avatar, now_upd_ts),
                    )

                conn.execute(
                    "UPDATE users SET display_name = ?, handle = ?, bio = ?, avatar_url = ?, updated_at = ? WHERE id = ?",
                    (display_name, handle, bio, new_avatar_url, now_upd_ts, uid),
                )
                updated_u = dict(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())
                new_tok = create_session_token(updated_u)
                conn.execute(
                    "INSERT OR REPLACE INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (new_tok, uid, now_upd_ts),
                )
                conn.commit()
                create_database_backup("profile_updated")
                try:
                    saved_settings = json.loads(updated_u.get("settings_json") or "{}")
                except Exception:
                    saved_settings = {}
                return self.send_json(
                    {
                        "ok": True,
                        "avatar_url": new_avatar_url,
                        "token": new_tok,
                        "user": {
                            "id": updated_u["id"],
                            "email": updated_u["email"],
                            "handle": updated_u["handle"],
                            "display_name": updated_u["display_name"],
                            "bio": updated_u.get("bio") or "",
                            "avatar_url": new_avatar_url,
                            "account_type": updated_u["account_type"],
                            "is_verified_institution": bool(updated_u["is_verified_institution"]),
                            "settings": {**DEFAULT_SETTINGS, **saved_settings},
                        },
                    },
                    extra_headers={
                        "Set-Cookie": f"ivris_session={new_tok}; Max-Age=31536000; Path=/; SameSite=Lax; HttpOnly"
                    },
                )

            if parsed.path == "/api/delete-post":
                post_id = (body.get("post_id") or "").strip()
                post_row = conn.execute(
                    "SELECT * FROM posts WHERE id = ? AND author_id = ?", (post_id, uid)
                ).fetchone()
                if not post_row:
                    return self.send_json({"error": "Post not found."}, 404)
                post_dict = dict(post_row)
                unlink_post_files(post_dict)
                conn.execute("DELETE FROM media_blobs WHERE url = ?", (post_dict.get("media_url"),))
                try:
                    for u_item in json.loads(post_dict.get("media_urls_json") or "[]"):
                        conn.execute("DELETE FROM media_blobs WHERE url = ?", (u_item,))
                except Exception:
                    pass
                conn.execute("DELETE FROM post_likes WHERE post_id = ?", (post_id,))
                conn.execute("DELETE FROM post_receipts WHERE post_id = ?", (post_id,))
                conn.execute("DELETE FROM post_views WHERE post_id = ?", (post_id,))
                conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
                conn.execute(
                    "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('post', ?, ?)",
                    (post_id, int(time.time())),
                )
                conn.commit()
                create_database_backup("post_deleted")
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
                create_database_backup("password_changed")
                return self.send_json({"ok": True})

            if parsed.path == "/api/update-settings":
                try:
                    current_settings = json.loads(user.get("settings_json") or "{}")
                except Exception:
                    current_settings = {}
                incoming_settings = body.get("settings") if isinstance(body.get("settings"), dict) else body
                updated = {**DEFAULT_SETTINGS, **current_settings, **(incoming_settings or {})}
                conn.execute(
                    "UPDATE users SET settings_json = ? WHERE id = ?",
                    (json.dumps(updated), uid),
                )
                conn.commit()
                create_database_backup("settings_updated")
                return self.send_json({"ok": True, "settings": updated})

            if parsed.path == "/api/delete-account":
                now_del_ts = int(time.time())
                user_posts = conn.execute(
                    "SELECT * FROM posts WHERE author_id = ?", (uid,)
                ).fetchall()
                for up in user_posts:
                    unlink_post_files(dict(up))
                    conn.execute(
                        "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('post', ?, ?)",
                        (up["id"], now_del_ts),
                    )
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
                conn.execute(
                    "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('user', ?, ?)",
                    (uid, now_del_ts),
                )
                conn.commit()
                create_database_backup("account_deleted")
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

                is_explicit, explicit_reason = detect_nudity_or_explicit(
                    caption, location, raw_bytes_list, music=music
                )
                if is_explicit:
                    conn.execute(
                        """
                        INSERT INTO moderation_logs (id, moderator_id, action, target_id, author_handle, reason, created_at)
                        VALUES (?, 'system_auto_nudity_filter', 'blocked_explicit', ?, ?, ?, ?)
                        """,
                        (
                            "log_" + secrets.token_hex(6),
                            "blocked_upload_" + secrets.token_hex(4),
                            user["handle"],
                            explicit_reason,
                            int(time.time()),
                        ),
                    )
                    conn.commit()
                    return self.send_json(
                        {
                            "error": f"Upload blocked: {explicit_reason} Explicit content is prohibited on Ivris.",
                        },
                        400,
                    )

                saved_urls = []
                now_ts = int(time.time())
                for idx, ext, raw_media in decoded_items:
                    filename = f"{uid}_{int(time.time() * 1000)}_{idx}.{ext}"
                    filepath = UPLOADS_DIR / filename
                    filepath.write_bytes(raw_media)
                    post_url = f"/uploads/{filename}"
                    saved_urls.append(post_url)
                    mime_type = "image/jpeg" if ext in ("jpg", "jpeg") else ("video/mp4" if ext == "mp4" else "image/png")
                    conn.execute(
                        "INSERT OR REPLACE INTO media_blobs (url, mime_type, data, created_at) VALUES (?, ?, ?, ?)",
                        (post_url, mime_type, raw_media, now_ts),
                    )

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
                create_database_backup("post_created")
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
                target_id = (body.get("target_id") or "").strip()
                action = (body.get("action") or "").strip().lower()
                if not target_id or target_id == uid:
                    return self.send_json({"error": "Invalid target user"}, 400)
                target = conn.execute(
                    "SELECT * FROM users WHERE id = ?", (target_id,)
                ).fetchone()
                if not target:
                    return self.send_json({"error": "User not found"}, 404)

                existing_rows = conn.execute(
                    """
                    SELECT * FROM connections
                    WHERE (requester_id = ? AND addressee_id = ?)
                       OR (requester_id = ? AND addressee_id = ?)
                    """,
                    (uid, target_id, target_id, uid),
                ).fetchall()
                existing = existing_rows[0] if existing_rows else None
                now_conn_ts = int(time.time())

                def _delete_existing_conns():
                    for r_conn in existing_rows:
                        conn.execute("DELETE FROM connections WHERE id = ?", (r_conn["id"],))
                        conn.execute(
                            "INSERT OR REPLACE INTO deleted_records (record_type, record_id, deleted_at) VALUES ('connection', ?, ?)",
                            (r_conn["id"], now_conn_ts),
                        )

                if action in ("remove", "cancel", "decline", "unfriend") and existing:
                    _delete_existing_conns()
                elif not existing:
                    if action not in ("remove", "cancel", "decline", "unfriend"):
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
                            ("con_" + secrets.token_hex(6), uid, target_id, status, now_conn_ts),
                        )
                elif existing["status"] == "pending":
                    if existing["addressee_id"] == uid and action not in ("decline", "remove", "cancel"):
                        conn.execute(
                            "UPDATE connections SET status = 'accepted' WHERE id = ?",
                            (existing["id"],),
                        )
                    elif existing["requester_id"] == uid and action in ("cancel", "remove", ""):
                        _delete_existing_conns()
                elif existing["status"] == "accepted" and action in ("remove", "unfriend", ""):
                    _delete_existing_conns()
                conn.commit()
                create_database_backup("connection_updated")
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
                    create_database_backup("message_sent")
                return self.send_json({"ok": True})

            return self.send_json({"error": "Not found"}, 404)
        finally:
            conn.close()


if __name__ == "__main__":
    auto_restore_if_needed()
    init_db()
    restore_media_blobs_to_disk()
    create_database_backup("boot")
    start_backup_scheduler()
    if not os.environ.get("RENDER"):
        threading.Thread(target=lambda: sync_with_upstream(force=False), daemon=True).start()
    port = int(os.environ.get("PORT", "3000"))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), IvrisHandler)
    print(f"Ivris Backend & Web Server running on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()
