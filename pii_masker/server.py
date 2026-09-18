"""ローカル GUI。

127.0.0.1 にのみバインドし、起動ごとに発行するトークンを持つリクエストだけを
受け付ける。外部への通信は一切行わず、CDN も使わない。
"""

from __future__ import annotations

import json
import re
import secrets
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .detectors import CATEGORIES, DEFAULT_CATEGORIES
from .documents import SUPPORTED_SUFFIXES, UnsupportedFile, mask_file
from .masker import MaskConfig, Vault, leftover_placeholders, restore_text
from . import store

ASSET_DIR = Path(__file__).parent / "assets"
MAX_BODY = 64 * 1024 * 1024  # 64MB


class Session:
    """GUI 1 起動分の状態（トークンと処理済みファイルの一時置き場）。"""

    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(24)
        self.tempdir = Path(tempfile.mkdtemp(prefix="pii-masker-"))
        self.downloads: dict[str, Path] = {}
        self.lock = threading.Lock()

    def register(self, path: Path) -> str:
        key = secrets.token_urlsafe(8)
        with self.lock:
            self.downloads[key] = path
        return key


SESSION = Session()


def _config_from(payload: dict) -> MaskConfig:
    categories = payload.get("categories") or list(DEFAULT_CATEGORIES)
    categories = [c for c in categories if c in CATEGORIES]
    terms = []
    for line in (payload.get("terms") or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            value, _, label = line.partition("\t")
            terms.append((value.strip(), (label or "機密語").strip()))
    allowlist = store.load_allow_domains()
    for line in (payload.get("allow_domains") or "").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line.startswith("-"):
            allowlist.discard(line[1:].strip())
        elif line:
            allowlist.add(line.lstrip("*."))
    return MaskConfig(
        categories=categories or list(DEFAULT_CATEGORIES),
        custom_terms=terms,
        all_dates=bool(payload.get("all_dates")),
        redact=bool(payload.get("redact")),
        url_mode="full" if payload.get("url_full") else "domain",
        org_guess=payload.get("org_guess", True),
        domain_allowlist=allowlist,
    )


def _parse_multipart(body: bytes, boundary: bytes) -> tuple[dict[str, str], list[tuple[str, bytes]]]:
    fields: dict[str, str] = {}
    files: list[tuple[str, bytes]] = []
    for chunk in body.split(b"--" + boundary):
        if not chunk or chunk in (b"--", b"--\r\n"):
            continue
        chunk = chunk[2:] if chunk.startswith(b"\r\n") else chunk
        chunk = chunk[:-2] if chunk.endswith(b"\r\n") else chunk
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        headers = head.decode("utf-8", "replace")
        filename = re.search(r'filename="([^"]*)"', headers)
        name = re.search(r'name="([^"]*)"', headers)
        if filename and filename.group(1):
            files.append((Path(filename.group(1)).name, data))
        elif name:
            fields[name.group(1)] = data.decode("utf-8", "replace")
    return fields, files


class Handler(BaseHTTPRequestHandler):
    server_version = "pii-masker"
    protocol_version = "HTTP/1.1"

    # --- 共通 ---------------------------------------------------
    def log_message(self, fmt, *args):  # アクセスログは出さない
        pass

    def _authorized(self, query: dict) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost", "[::1]", "::1"):
            return False
        token = self.headers.get("X-Token") or (query.get("token", [""])[0])
        return secrets.compare_digest(token or "", SESSION.token)

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, message: str, status: int = HTTPStatus.BAD_REQUEST) -> None:
        self._json({"error": message}, status)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ValueError("データが大きすぎます")
        return self.rfile.read(length) if length else b""

    # --- ルーティング -------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path in ("/", "/index.html"):
            if not self._authorized(query):
                self._send(HTTPStatus.FORBIDDEN, "トークンが不正です".encode(), "text/plain; charset=utf-8")
                return
            html = (ASSET_DIR / "index.html").read_text(encoding="utf-8")
            html = html.replace("__TOKEN__", SESSION.token)
            labels = {"URL": "URL・ドメイン"}
            html = html.replace("__CATEGORIES__", json.dumps(
                [{"key": k, "label": labels.get(k, v[0])}
                 for k, v in CATEGORIES.items() if k != "USER"],
                ensure_ascii=False))
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            return

        if not self._authorized(query):
            self._error("トークンが不正です", HTTPStatus.FORBIDDEN)
            return

        if parsed.path == "/api/download":
            key = query.get("id", [""])[0]
            path = SESSION.downloads.get(key)
            if not path or not path.exists():
                self._error("ファイルが見つかりません", HTTPStatus.NOT_FOUND)
                return
            data = path.read_bytes()
            quoted = path.name.encode("utf-8").decode("latin-1", "replace")
            self._send(200, data, "application/octet-stream",
                       {"Content-Disposition": f'attachment; filename="{quoted}"'})
            return

        if parsed.path == "/api/mappings":
            entries = [
                {"path": str(e["path"]), "name": e["path"].name,
                 "created_at": e["created_at"], "source": e["source"], "count": e["count"]}
                for e in store.list_mappings()
            ]
            self._json({"mappings": entries})
            return

        self._error("不明なパスです", HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._authorized(query):
            self._error("トークンが不正です", HTTPStatus.FORBIDDEN)
            return
        try:
            body = self._read_body()
        except ValueError as exc:
            self._error(str(exc), HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        try:
            if parsed.path == "/api/mask":
                self._handle_mask(json.loads(body or b"{}"))
            elif parsed.path == "/api/restore":
                self._handle_restore(json.loads(body or b"{}"))
            elif parsed.path == "/api/upload":
                self._handle_upload(body)
            elif parsed.path == "/api/purge":
                removed = store.purge(None)
                self._json({"removed": removed})
            else:
                self._error("不明なパスです", HTTPStatus.NOT_FOUND)
        except UnsupportedFile as exc:
            self._error(str(exc))
        except Exception as exc:  # GUI を落とさず理由を返す
            self._error(f"{type(exc).__name__}: {exc}", HTTPStatus.INTERNAL_SERVER_ERROR)

    # --- ハンドラ -----------------------------------------------
    def _handle_mask(self, payload: dict) -> None:
        text = payload.get("text") or ""
        config = _config_from(payload)
        vault = Vault(config)
        result = vault.mask(text)
        mapping_path = None
        if vault.mapping and not config.redact and payload.get("save", True):
            mapping_path = str(store.save_mapping(vault.mapping, source="gui-text"))
        self._json({
            "text": result.text,
            "summary": result.summary(),
            "hits": [{k: h[k] for k in ("display", "value", "replacement", "rule")}
                     for h in result.hits],
            "mapping": vault.mapping,
            "mapping_path": mapping_path,
        })

    def _handle_restore(self, payload: dict) -> None:
        text = payload.get("text") or ""
        if payload.get("mapping_path"):
            mapping = store.load_mapping(Path(payload["mapping_path"]))
        elif payload.get("mapping"):
            mapping = payload["mapping"]
        else:
            mapping = store.merged_mapping()
        restored, count = restore_text(text, mapping)
        self._json({
            "text": restored,
            "count": count,
            "leftover": leftover_placeholders(restored),
        })

    def _handle_upload(self, body: bytes) -> None:
        content_type = self.headers.get("Content-Type") or ""
        match = re.search(r"boundary=([^;]+)", content_type)
        if not match:
            self._error("multipart の boundary がありません")
            return
        boundary = match.group(1).strip('"').encode()
        fields, files = _parse_multipart(body, boundary)
        if not files:
            self._error("ファイルがありません")
            return

        config = _config_from(json.loads(fields.get("options") or "{}"))
        vault = Vault(config)
        pdf_mode = json.loads(fields.get("options") or "{}").get("pdf_mode", "text")

        results = []
        workdir = Path(tempfile.mkdtemp(dir=SESSION.tempdir))
        for name, data in files:
            suffix = Path(name).suffix.lower()
            if suffix not in SUPPORTED_SUFFIXES:
                results.append({"name": name, "error": f"未対応の形式です ({suffix or '拡張子なし'})"})
                continue
            source = workdir / name
            source.write_bytes(data)
            try:
                outcome = mask_file(source, vault, pdf_mode=pdf_mode)
            except UnsupportedFile as exc:
                results.append({"name": name, "error": str(exc)})
                continue
            key = SESSION.register(outcome.output)
            results.append({
                "name": name,
                "output": outcome.output.name,
                "download": key,
                "summary": outcome.result.summary(),
                "note": outcome.note,
                "hits": [{k: h[k] for k in ("display", "value", "replacement")}
                         for h in outcome.result.hits],
            })

        mapping_path = None
        if vault.mapping and not config.redact:
            mapping_path = str(store.save_mapping(vault.mapping, source="gui-files"))
        self._json({"files": results, "mapping": vault.mapping, "mapping_path": mapping_path})


def serve(host: str = "127.0.0.1", port: int = 0, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost"):
        raise SystemExit("安全のため 127.0.0.1 以外では起動できません")
    httpd = ThreadingHTTPServer((host, port), Handler)
    actual_port = httpd.server_address[1]
    url = f"http://127.0.0.1:{actual_port}/?token={SESSION.token}"
    print("pii-masker GUI を起動しました（このマシンの中だけで動作します）")
    print(f"  {url}")
    print("  終了するには Ctrl+C", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n終了しました")
    finally:
        httpd.server_close()
