"""マッピング（元の値 ↔ プレースホルダ）の保存と読み込み。

対応表には個人情報そのものが平文で入るため、
パーミッションを 0600 に固定し、保存先を 1 箇所に集約する。
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

HOME_DIR = Path(os.environ.get("PII_MASKER_HOME", Path.home() / ".pii-masker"))
STORE_DIR = HOME_DIR / "mappings"
ALLOW_DOMAINS_FILE = HOME_DIR / "allow-domains.txt"


def ensure_store() -> Path:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STORE_DIR, 0o700)
    return STORE_DIR


def _slug(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9ぁ-んァ-ヶ一-龥\-_]+", "-", name).strip("-")
    return (slug or "text")[:40]


def save_mapping(mapping: dict[str, str], *, source: str = "text", path: Path | None = None) -> Path:
    ensure_store()
    if path is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = STORE_DIR / f"{stamp}-{_slug(source)}.json"
    payload = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "source": source,
        "count": len(mapping),
        "mapping": mapping,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def load_mapping(path: Path) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "mapping" in data:
        return data["mapping"]
    if isinstance(data, dict):
        return data  # 素の dict 形式も許容
    raise ValueError(f"マッピングファイルの形式が不正です: {path}")


def list_mappings() -> list[dict]:
    ensure_store()
    out = []
    for path in sorted(STORE_DIR.glob("*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        out.append(
            {
                "path": path,
                "created_at": data.get("created_at", ""),
                "source": data.get("source", ""),
                "count": data.get("count", len(data.get("mapping", {}))),
            }
        )
    return out


def latest_mapping() -> Path | None:
    entries = list_mappings()
    return entries[0]["path"] if entries else None


def merged_mapping(limit: int = 50) -> dict[str, str]:
    """直近のマッピングを新しい順に統合する（復元時の総当たり用）。"""
    merged: dict[str, str] = {}
    for entry in list_mappings()[:limit]:
        for key, value in load_mapping(entry["path"]).items():
            merged.setdefault(key, value)
    return merged


def purge(older_than_days: int | None = None) -> int:
    """対応表を削除する。日数指定がなければ全削除。"""
    ensure_store()
    removed = 0
    cutoff = time.time() - timedelta(days=older_than_days or 0).total_seconds()
    for path in STORE_DIR.glob("*.json"):
        if older_than_days is not None and path.stat().st_mtime > cutoff:
            continue
        path.unlink()
        removed += 1
    return removed


def load_allow_domains(path: Path | None = None) -> set[str]:
    """マスクしないドメインの一覧。内蔵リストにユーザー設定を足して返す。"""
    from .lexicon import DEFAULT_DOMAIN_ALLOWLIST

    allowed = set(DEFAULT_DOMAIN_ALLOWLIST)
    target = path or ALLOW_DOMAINS_FILE
    if not target.exists():
        return allowed
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if line.startswith("-"):          # 内蔵リストから外したいとき
            allowed.discard(line[1:].strip())
        else:
            allowed.add(line.lstrip("*."))
    return allowed
