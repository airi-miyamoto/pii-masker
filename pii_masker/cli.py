"""コマンドラインインターフェース。"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import __version__
from .detectors import CATEGORIES, DEFAULT_CATEGORIES
from .documents import SUPPORTED_SUFFIXES, UnsupportedFile, mask_file, read_any
from .masker import MaskConfig, Vault, leftover_placeholders, restore_text
from . import store

DEFAULT_TERMS_FILE = store.STORE_DIR.parent / "terms.txt"


def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


def load_terms(path: Path | None) -> list[tuple[str, str]]:
    """ユーザー辞書を読む。1行1語、`値<TAB>ラベル` 形式も可。"""
    target = path or DEFAULT_TERMS_FILE
    if not target.exists():
        if path is not None:
            raise SystemExit(f"辞書ファイルが見つかりません: {target}")
        return []
    terms: list[tuple[str, str]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            value, label = line.split("\t", 1)
        else:
            value, label = line, "機密語"
        terms.append((value.strip(), label.strip()))
    return terms


def build_config(args) -> MaskConfig:
    categories = list(DEFAULT_CATEGORIES)
    if getattr(args, "only", None):
        requested = [c.strip().upper() for c in args.only.split(",") if c.strip()]
        unknown = [c for c in requested if c not in CATEGORIES]
        if unknown:
            raise SystemExit(f"不明なカテゴリ: {', '.join(unknown)}")
        categories = requested
    if getattr(args, "skip", None):
        skipped = {c.strip().upper() for c in args.skip.split(",") if c.strip()}
        unknown = [c for c in skipped if c not in CATEGORIES]
        if unknown:
            raise SystemExit(f"不明なカテゴリ: {', '.join(unknown)}")
        categories = [c for c in categories if c not in skipped]
    allow_file = getattr(args, "allow_domains", None)
    return MaskConfig(
        categories=categories,
        custom_terms=load_terms(Path(args.terms) if getattr(args, "terms", None) else None),
        all_dates=getattr(args, "all_dates", False),
        redact=getattr(args, "redact", False),
        url_mode="full" if getattr(args, "url_full", False) else "domain",
        org_guess=not getattr(args, "no_org_guess", False),
        domain_allowlist=store.load_allow_domains(Path(allow_file) if allow_file else None),
    )


def _print_summary(summary: dict[str, int], prefix: str = "") -> None:
    if not summary:
        _eprint(f"{prefix}検出なし")
        return
    parts = [f"{label} {count}件" for label, count in sorted(summary.items())]
    _eprint(f"{prefix}{' / '.join(parts)}")


# --- mask -------------------------------------------------------------

def cmd_mask(args) -> int:
    config = build_config(args)
    vault = Vault(config)
    if args.mapping:
        vault.load_mapping(store.load_mapping(Path(args.mapping)))

    if not args.paths:
        text = sys.stdin.read()
        result = vault.mask(text)
        sys.stdout.write(result.text)
        _print_summary(result.summary())
        _save(vault, args, source="stdin")
        return 0

    outcomes = []
    for raw in args.paths:
        path = Path(raw)
        targets = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for target in targets:
            if path.is_dir() and target.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            try:
                outcome = mask_file(
                    target,
                    vault,
                    output=Path(args.out) if args.out and len(targets) == 1 else None,
                    pdf_mode=args.pdf_mode,
                )
            except UnsupportedFile as exc:
                _eprint(f"skip: {exc}")
                continue
            outcomes.append(outcome)
            summary = " / ".join(
                f"{k} {v}件" for k, v in sorted(outcome.result.summary().items())
            ) or "検出なし"
            note = f"  ({outcome.note})" if outcome.note else ""
            print(f"{target} -> {outcome.output}\n  {summary}{note}")

    if outcomes:
        _save(vault, args, source=Path(args.paths[0]).name)
    return 0 if outcomes or not args.paths else 1


def _save(vault: Vault, args, *, source: str) -> None:
    if vault.config.redact or args.no_save or not vault.mapping:
        return
    path = store.save_mapping(vault.mapping, source=source,
                              path=Path(args.save_mapping) if args.save_mapping else None)
    _eprint(f"対応表: {path}")


# --- restore ----------------------------------------------------------

def cmd_restore(args) -> int:
    if args.mapping:
        mapping = store.load_mapping(Path(args.mapping))
    elif args.all_mappings:
        mapping = store.merged_mapping()
    else:
        latest = store.latest_mapping()
        if latest is None:
            raise SystemExit("対応表が見つかりません。--mapping で指定してください。")
        mapping = store.load_mapping(latest)
        _eprint(f"対応表: {latest}")

    if args.path:
        path = Path(args.path)
        text = read_any(path)
    else:
        text = sys.stdin.read()

    restored, count = restore_text(text, mapping)
    if args.out:
        Path(args.out).write_text(restored, encoding="utf-8")
        print(f"-> {args.out}")
    else:
        sys.stdout.write(restored)

    _eprint(f"{count} 箇所を復元")
    leftover = leftover_placeholders(restored)
    if leftover:
        _eprint(f"注意: 対応表に無いプレースホルダが残っています: {', '.join(leftover)}")
    return 0


# --- detect -----------------------------------------------------------

def cmd_detect(args) -> int:
    config = build_config(args)
    vault = Vault(config)
    text = read_any(Path(args.path)) if args.path else sys.stdin.read()
    result = vault.mask(text)

    if args.json:
        print(json.dumps(
            [{k: h[k] for k in ("display", "value", "replacement", "rule", "start", "end")}
             for h in result.hits],
            ensure_ascii=False, indent=2,
        ))
        return 0

    if not result.hits:
        print("検出なし")
        return 0
    width = max(len(h["display"]) for h in result.hits)
    for hit in result.hits:
        print(f"{hit['display']:<{width}}  {hit['value']}  ->  {hit['replacement']}  [{hit['rule']}]")
    print()
    _print_summary(result.summary(), prefix="合計: ")
    return 0


# --- clip -------------------------------------------------------------

def _pbpaste() -> str:
    return subprocess.run(["pbpaste"], capture_output=True, text=True, check=True).stdout


def _pbcopy(text: str) -> None:
    subprocess.run(["pbcopy"], input=text, text=True, check=True)


def cmd_clip(args) -> int:
    config = build_config(args)
    vault = Vault(config)
    text = _pbpaste()
    if not text.strip():
        raise SystemExit("クリップボードが空です")
    result = vault.mask(text)
    _pbcopy(result.text)
    _print_summary(result.summary(), prefix="クリップボードを置換: ")
    _save(vault, args, source="clipboard")
    return 0


def cmd_clip_restore(args) -> int:
    mapping = (store.load_mapping(Path(args.mapping)) if args.mapping
               else store.merged_mapping())
    if not mapping:
        raise SystemExit("対応表が見つかりません")
    restored, count = restore_text(_pbpaste(), mapping)
    _pbcopy(restored)
    _eprint(f"クリップボードの {count} 箇所を復元")
    return 0


# --- mappings ---------------------------------------------------------

def cmd_mappings(args) -> int:
    if args.action == "list":
        entries = store.list_mappings()
        if not entries:
            print("対応表はありません")
            return 0
        for entry in entries:
            print(f"{entry['created_at']}  {entry['count']:>4}件  {entry['source']}\n    {entry['path']}")
        return 0
    if args.action == "show":
        path = Path(args.target) if args.target else store.latest_mapping()
        if path is None:
            raise SystemExit("対応表が見つかりません")
        mapping = store.load_mapping(path)
        for placeholder, original in mapping.items():
            print(f"{placeholder}\t{original}")
        return 0
    if args.action == "purge":
        removed = store.purge(args.older_than)
        print(f"{removed} 件の対応表を削除しました")
        return 0
    raise SystemExit(f"不明な操作: {args.action}")


# --- gui --------------------------------------------------------------

def cmd_gui(args) -> int:
    from .server import serve

    serve(host=args.host, port=args.port, open_browser=not args.no_browser)
    return 0


# --- パーサ -----------------------------------------------------------

def _add_mask_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--only", help="対象カテゴリをカンマ区切りで限定 (例: NAME,EMAIL)")
    parser.add_argument("--skip", help="除外するカテゴリをカンマ区切りで指定")
    parser.add_argument("--terms", help="ユーザー辞書ファイル (既定: ~/.pii-masker/terms.txt)")
    parser.add_argument("--all-dates", action="store_true",
                        help="生年月日ラベルの無い日付もすべてマスクする")
    parser.add_argument("--url-full", action="store_true",
                        help="URL をドメインだけでなく全体（パス・クエリ含む）マスクする")
    parser.add_argument("--allow-domains",
                        help="マスクしないドメインの一覧ファイル (既定: ~/.pii-masker/allow-domains.txt)")
    parser.add_argument("--no-org-guess", action="store_true",
                        help="「〜工務店」「〜不動産」など法人格の無い社名の推測をやめる")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mask",
        description="ローカル完結の個人情報マスキングツール（外部通信なし）",
    )
    parser.add_argument("--version", action="version", version=f"pii-masker {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_mask = sub.add_parser("mask", help="ファイル/標準入力をマスクする")
    p_mask.add_argument("paths", nargs="*", help="対象ファイルまたはディレクトリ")
    p_mask.add_argument("-o", "--out", help="出力先（単一ファイル指定時のみ）")
    p_mask.add_argument("--redact", action="store_true", help="復元不能な伏字にする")
    p_mask.add_argument("--pdf-mode", choices=("text", "redact"), default="text",
                        help="PDF の扱い: text=テキスト抽出(既定) / redact=黒塗りPDF")
    p_mask.add_argument("--mapping", help="既存の対応表を引き継いで採番する")
    p_mask.add_argument("--save-mapping", help="対応表の保存先を明示する")
    p_mask.add_argument("--no-save", action="store_true", help="対応表を保存しない")
    _add_mask_options(p_mask)
    p_mask.set_defaults(func=cmd_mask)

    p_restore = sub.add_parser("restore", help="プレースホルダを元の値に戻す")
    p_restore.add_argument("path", nargs="?", help="対象ファイル（省略時は標準入力）")
    p_restore.add_argument("-o", "--out", help="出力先")
    p_restore.add_argument("--mapping", help="使用する対応表")
    p_restore.add_argument("--all-mappings", action="store_true",
                           help="保存済みの対応表をすべて統合して復元する")
    p_restore.set_defaults(func=cmd_restore)

    p_detect = sub.add_parser("detect", help="何が検出されるかだけ確認する（書き換えない）")
    p_detect.add_argument("path", nargs="?", help="対象ファイル（省略時は標準入力）")
    p_detect.add_argument("--json", action="store_true", help="JSON で出力")
    _add_mask_options(p_detect)
    p_detect.set_defaults(func=cmd_detect)

    p_clip = sub.add_parser("clip", help="クリップボードの中身をマスクして書き戻す")
    p_clip.add_argument("--redact", action="store_true", help="復元不能な伏字にする")
    p_clip.add_argument("--no-save", action="store_true", help="対応表を保存しない")
    p_clip.add_argument("--save-mapping", help="対応表の保存先を明示する")
    _add_mask_options(p_clip)
    p_clip.set_defaults(func=cmd_clip)

    p_unclip = sub.add_parser("unclip", help="クリップボードの中身を復元する")
    p_unclip.add_argument("--mapping", help="使用する対応表")
    p_unclip.set_defaults(func=cmd_clip_restore)

    p_map = sub.add_parser("mappings", help="対応表の一覧・表示・削除")
    p_map.add_argument("action", choices=("list", "show", "purge"))
    p_map.add_argument("target", nargs="?", help="show の対象ファイル")
    p_map.add_argument("--older-than", type=int, metavar="DAYS",
                       help="purge 時、指定日数より古いものだけ削除")
    p_map.set_defaults(func=cmd_mappings)

    p_gui = sub.add_parser("gui", help="ブラウザ GUI を起動する")
    p_gui.add_argument("--port", type=int, default=0, help="待ち受けポート（既定: 空きポート）")
    p_gui.add_argument("--host", default="127.0.0.1", help="待ち受けアドレス")
    p_gui.add_argument("--no-browser", action="store_true", help="ブラウザを自動で開かない")
    p_gui.set_defaults(func=cmd_gui)

    return parser


KNOWN_COMMANDS = {"mask", "restore", "detect", "clip", "unclip", "mappings", "gui"}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # 引数なし／パス直指定のときは mask サブコマンドとみなす
    if not argv or (argv[0] not in KNOWN_COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv = ["mask"] + argv
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        _eprint("中断しました")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
