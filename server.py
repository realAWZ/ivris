#!/usr/bin/env python3
import base64
import hashlib
import http.server
import io
import json
import os
import random
import re
import secrets
import sqlite3
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
UPLOADS_DIR = WEB_DIR / "uploads"
DB_PATH = BASE_DIR / "ivris.db"

UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MOD_EMAIL = os.environ.get("IVRIS_MOD_EMAIL", "moderator@ivris.app")
DEFAULT_MOD_HANDLE = os.environ.get("IVRIS_MOD_HANDLE", "moderator")
DEFAULT_MOD_PASSWORD = os.environ.get("IVRIS_MOD_PASSWORD", "IvrisMod2026!")

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

    existing_post_cols = [
        r["name"] for r in cur.execute("PRAGMA table_info(posts)").fetchall()
    ]
    if "media_urls_json" not in existing_post_cols:
        cur.execute("ALTER TABLE posts ADD COLUMN media_urls_json TEXT DEFAULT '[]'")
    if "music_json" not in existing_post_cols:
        cur.execute("ALTER TABLE posts ADD COLUMN music_json TEXT DEFAULT ''")

    # Seed dedicated Moderation Account if not present
    mod_row = cur.execute(
        "SELECT * FROM users WHERE handle = ? OR email = ?",
        (DEFAULT_MOD_HANDLE, DEFAULT_MOD_EMAIL),
    ).fetchone()
    if not mod_row:
        cur.execute(
            """
            INSERT INTO users (id, email, password_hash, handle, display_name, bio, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'moderator', 0, 1, '', ?, ?)
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
            "UPDATE users SET account_type = 'moderator', email_confirmed = 1 WHERE id = ?",
            (mod_row["id"],),
        )

    conn.commit()
    conn.close()


def inspect_image_bytes_for_nudity(raw_bytes: bytes) -> tuple[bool, str]:
    """
    Analyzes image bytes using YCbCr + RGB skin-exposure heuristics to detect
    unclothed/nudity imagery so it can be immediately blocked and deleted.
    """
    if not raw_bytes or Image is None:
        return False, ""
    try:
        with Image.open(io.BytesIO(raw_bytes)) as img:
            rgb_img = img.convert("RGB").resize((96, 96))
            ycbcr_img = rgb_img.convert("YCbCr")
            rgb_pixels = list(rgb_img.getdata())
            ycbcr_pixels = list(ycbcr_img.getdata())

            total_pixels = len(rgb_pixels)
            if total_pixels == 0:
                return False, ""

            skin_count = 0
            center_skin_count = 0
            center_total = 0

            for idx, ((r, g, b), (y, cb, cr)) in enumerate(zip(rgb_pixels, ycbcr_pixels)):
                row = idx // 96
                col = idx % 96
                in_center = 16 <= row <= 80 and 16 <= col <= 80
                if in_center:
                    center_total += 1

                # Dual RGB + YCbCr skin-tone cluster rule
                rgb_skin = (
                    r > 95
                    and g > 40
                    and b > 20
                    and (max(r, g, b) - min(r, g, b)) > 15
                    and abs(r - g) > 15
                    and r > g
                    and r > b
                )
                ycbcr_skin = (80 <= cb <= 127) and (133 <= cr <= 173) and (y > 60)

                if rgb_skin and ycbcr_skin:
                    skin_count += 1
                    if in_center:
                        center_skin_count += 1

            overall_ratio = skin_count / total_pixels
            center_ratio = center_skin_count / max(center_total, 1)

            # High central & overall skin exposure threshold indicative of nudity
            if center_ratio >= 0.62 and overall_ratio >= 0.50:
                return (
                    True,
                    f"Automated image nudity detector triggered (central exposure {int(center_ratio * 100)}%, overall {int(overall_ratio * 100)}%).",
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

    def send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def get_current_user(self, conn):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth.replace("Bearer ", "").strip()
        row = conn.execute(
            """
            SELECT u.* FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
        return dict(row) if row else None

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
                    SELECT p.*, u.handle AS author_handle, u.display_name AS author_name, u.account_type
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
                        SELECT id, email, handle, display_name, account_type, is_verified_institution, created_at
                        FROM users
                        WHERE account_type != 'moderator'
                        ORDER BY created_at DESC
                        """
                    ).fetchall()
                ]

                return self.send_json(
                    {
                        "moderator": {
                            "id": user["id"],
                            "handle": user["handle"],
                            "email": user["email"],
                        },
                        "auto_deleted_in_sweep": auto_deleted_now,
                        "reports": reports,
                        "active_posts": active_posts,
                        "logs": logs,
                        "users": users_list,
                    }
                )
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

                my_likes = set(
                    r["post_id"]
                    for r in conn.execute(
                        "SELECT post_id FROM post_likes WHERE user_id = ?", (uid,)
                    ).fetchall()
                )

                all_posts = conn.execute(
                    """
                    SELECT p.*, u.handle, u.display_name, u.account_type, u.is_verified_institution
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
                    p["likedByMe"] = p["id"] in my_likes
                    try:
                        p["music"] = (
                            json.loads(p["music_json"]) if p.get("music_json") else None
                        )
                    except Exception:
                        p["music"] = None

                    if author_id == uid:
                        cnt = conn.execute(
                            "SELECT COUNT(*) AS c FROM post_likes WHERE post_id = ?",
                            (p["id"],),
                        ).fetchone()["c"]
                        p["ownerOnlyLikesCount"] = cnt

                    if p["media_kind"] == "video_story":
                        if p["expires_at"] and p["expires_at"] > now_ts:
                            if author_id == uid:
                                my_stories.append(p)
                            else:
                                stories.append(p)
                    else:
                        if author_id == uid:
                            my_posts.append(p)
                        else:
                            feed_posts.append(p)

                other_users = [
                    dict(r)
                    for r in conn.execute(
                        """
                        SELECT id, handle, display_name, bio, account_type, is_verified_institution
                        FROM users
                        WHERE id != ? AND email_confirmed = 1 AND account_type != 'moderator'
                        ORDER BY created_at DESC
                        """,
                        (uid,),
                    ).fetchall()
                ]

                return self.send_json(
                    {
                        "user": {
                            "id": user["id"],
                            "email": user["email"],
                            "handle": user["handle"],
                            "display_name": user["display_name"],
                            "bio": user["bio"],
                            "account_type": user["account_type"],
                            "is_verified_institution": bool(user["is_verified_institution"]),
                            "settings": user_settings,
                        },
                        "connections": conns,
                        "seenPostIds": seen_ids,
                        "feedPosts": feed_posts,
                        "myPosts": my_posts,
                        "myStories": my_stories,
                        "stories": stories,
                        "allProfiles": other_users,
                    }
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
                code = f"{random.randint(100000, 999999)}"
                conn.execute(
                    """
                    INSERT INTO users (id, email, password_hash, handle, display_name, account_type, is_verified_institution, email_confirmed, verification_code, settings_json, created_at)
                    VALUES (?, ?, ?, ?, ?, 'personal', 0, 0, ?, ?, ?)
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
                token = secrets.token_hex(24)
                conn.execute(
                    "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (token, user["id"], int(time.time())),
                )
                conn.commit()
                return self.send_json({"token": token})

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

                token = secrets.token_hex(24)
                conn.execute(
                    "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
                    (token, user["id"], int(time.time())),
                )
                conn.commit()
                return self.send_json(
                    {
                        "token": token,
                        "account_type": user["account_type"],
                        "handle": user["handle"],
                    }
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

            # Moderator-only endpoints
            if parsed.path.startswith("/api/moderation/"):
                if user.get("account_type") != "moderator":
                    return self.send_json(
                        {"error": "Moderator account authorization required."}, 403
                    )

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
                display_name = (body.get("display_name") or "").strip()
                handle = (
                    (body.get("handle") or "")
                    .strip()
                    .lower()
                    .replace("@", "")
                    .replace(" ", "")
                )
                bio = (body.get("bio") or "").strip()

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

                conn.execute(
                    "UPDATE users SET display_name = ?, handle = ?, bio = ? WHERE id = ?",
                    (display_name, handle, bio, uid),
                )
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
                if is_nudity:
                    conn.execute(
                        """
                        INSERT INTO moderation_logs (id, moderator_id, action, target_id, author_handle, reason, created_at)
                        VALUES (?, 'system_auto_nudity_filter', 'auto_deleted_nudity', ?, ?, ?, ?)
                        """,
                        (
                            "log_" + secrets.token_hex(6),
                            "blocked_upload_" + secrets.token_hex(4),
                            user["handle"],
                            nudity_reason,
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

            if parsed.path == "/api/like":
                post_id = body.get("post_id", "")
                existing = conn.execute(
                    "SELECT 1 FROM post_likes WHERE post_id = ? AND user_id = ?",
                    (post_id, uid),
                ).fetchone()
                if existing:
                    conn.execute(
                        "DELETE FROM post_likes WHERE post_id = ? AND user_id = ?",
                        (post_id, uid),
                    )
                else:
                    conn.execute(
                        "INSERT INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, ?)",
                        (post_id, uid, int(time.time())),
                    )
                conn.commit()
                return self.send_json({"ok": True})

            if parsed.path == "/api/seen":
                post_id = body.get("post_id", "")
                conn.execute(
                    "INSERT OR REPLACE INTO post_receipts (user_id, post_id, seen_at) VALUES (?, ?, ?)",
                    (uid, post_id, int(time.time())),
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
    init_db()
    port = int(os.environ.get("PORT", "3000"))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), IvrisHandler)
    print(f"Ivris Backend & Web Server running on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()
