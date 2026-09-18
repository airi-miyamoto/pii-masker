"""ファイル形式ごとの読み書き。

txt / md / csv / json / html などのプレーンテキストに加え、
docx（書式を保ったまま置換）と pdf（テキスト抽出 or 黒塗り）に対応する。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .masker import MaskResult, Vault

TEXT_SUFFIXES = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".yaml", ".yml",
    ".html", ".htm", ".xml", ".log", ".sql", ".ini", ".conf", ".env", ".srt", ".vtt",
    ".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".css", ".scss",
}
DOCX_SUFFIXES = {".docx"}
PDF_SUFFIXES = {".pdf"}
SUPPORTED_SUFFIXES = TEXT_SUFFIXES | DOCX_SUFFIXES | PDF_SUFFIXES

ENCODINGS = ("utf-8", "utf-8-sig", "cp932", "euc-jp")


class UnsupportedFile(Exception):
    pass


@dataclass
class FileOutcome:
    source: Path
    output: Path | None
    result: MaskResult
    note: str = ""


# --- プレーンテキスト -------------------------------------------------

def read_text_file(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    for enc in ENCODINGS:
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    raise UnsupportedFile(f"文字コードを判別できません: {path}")


def _default_output(path: Path, vault: Vault, suffix: str | None = None) -> Path:
    tag = "redacted" if vault.config.redact else "masked"
    return path.with_name(f"{path.stem}.{tag}{suffix or path.suffix}")


def mask_text_file(path: Path, vault: Vault, output: Path | None = None) -> FileOutcome:
    text, encoding = read_text_file(path)
    result = vault.mask(text)
    out = output or _default_output(path, vault)
    out.write_text(result.text, encoding="utf-8")
    note = f"{encoding} で読み込み、UTF-8 で出力" if encoding != "utf-8" else ""
    return FileOutcome(path, out, result, note)


# --- docx -------------------------------------------------------------

def _mask_runs(runs, vault: Vault) -> list[dict]:
    """段落内の run をまたぐ置換に対応しつつ、書式を保ったまま置き換える。"""
    if not runs:
        return []
    full = "".join(run.text for run in runs)
    if not full.strip():
        return []
    result = vault.mask(full)
    if not result.hits:
        return []

    bounds, pos = [], 0
    for run in runs:
        bounds.append((pos, pos + len(run.text)))
        pos += len(run.text)
    buffers = [list(run.text) for run in runs]

    # 後ろの検出から適用してオフセットのずれを防ぐ
    for hit in sorted(result.hits, key=lambda h: h["start"], reverse=True):
        start, end, replacement = hit["start"], hit["end"], hit["replacement"]
        placed = False
        for index, (bstart, bend) in enumerate(bounds):
            if bend <= start or bstart >= end:
                continue
            local_start = max(start, bstart) - bstart
            local_end = min(end, bend) - bstart
            if placed:
                buffers[index][local_start:local_end] = []
            else:
                buffers[index][local_start:local_end] = list(replacement)
                placed = True

    for run, buffer in zip(runs, buffers):
        run.text = "".join(buffer)
    return result.hits


def _iter_docx_paragraphs(container):
    for paragraph in getattr(container, "paragraphs", []):
        yield paragraph
    for table in getattr(container, "tables", []):
        for row in table.rows:
            for cell in row.cells:
                yield from _iter_docx_paragraphs(cell)


def mask_docx_file(path: Path, vault: Vault, output: Path | None = None) -> FileOutcome:
    try:
        import docx  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise UnsupportedFile("docx を扱うには python-docx が必要です") from exc

    document = docx.Document(str(path))
    hits: list[dict] = []
    targets = [document]
    for section in document.sections:
        targets.extend([section.header, section.footer,
                        section.first_page_header, section.first_page_footer,
                        section.even_page_header, section.even_page_footer])
    for target in targets:
        if target is None:
            continue
        for paragraph in _iter_docx_paragraphs(target):
            hits.extend(_mask_runs(paragraph.runs, vault))

    out = output or _default_output(path, vault)
    document.save(str(out))
    result = MaskResult(text="", mapping=dict(vault.mapping), hits=hits)
    return FileOutcome(path, out, result, "書式を保持したまま置換")


# --- pdf --------------------------------------------------------------

def _import_pymupdf():
    """PyMuPDF を読み込む。新しい版の `pymupdf` を優先する。"""
    try:
        import pymupdf  # type: ignore

        return pymupdf
    except ImportError:
        import fitz  # type: ignore  # PyMuPDF 1.23 以前

        return fitz


def extract_pdf_text(path: Path) -> str:
    fitz = _import_pymupdf()

    with fitz.open(str(path)) as doc:
        pages = [page.get_text("text") for page in doc]
    return "\n\n".join(pages)


def mask_pdf_file(
    path: Path, vault: Vault, output: Path | None = None, mode: str = "text"
) -> FileOutcome:
    try:
        fitz = _import_pymupdf()
    except ImportError as exc:  # pragma: no cover
        raise UnsupportedFile("pdf を扱うには PyMuPDF が必要です") from exc

    if mode == "text":
        text = extract_pdf_text(path)
        result = vault.mask(text)
        out = output or _default_output(path, vault, suffix=".txt")
        out.write_text(result.text, encoding="utf-8")
        return FileOutcome(path, out, result, "PDF からテキストを抽出して出力")

    if mode != "redact":
        raise UnsupportedFile(f"不明な PDF モード: {mode}")

    # 黒塗りモード: レイアウトを保つが復元はできない
    text = extract_pdf_text(path)
    probe = Vault(vault.config)
    probe.load_mapping(vault.mapping)
    detected = probe.mask(text)
    values = sorted({hit["value"] for hit in detected.hits}, key=len, reverse=True)

    out = output or path.with_name(f"{path.stem}.redacted.pdf")
    applied = 0
    with fitz.open(str(path)) as doc:
        for page in doc:
            for value in values:
                for rect in page.search_for(value):
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    applied += 1
            page.apply_redactions()
        doc.save(str(out), garbage=3, deflate=True)

    note = f"{applied} 箇所を黒塗り（復元不可）"
    if not applied and values:
        note += " / 文字が画像化されている可能性があります"
    result = MaskResult(text="", mapping={}, hits=detected.hits)
    return FileOutcome(path, out, result, note)


# --- ディスパッチ -----------------------------------------------------

def mask_file(
    path: Path, vault: Vault, output: Path | None = None, pdf_mode: str = "text"
) -> FileOutcome:
    path = Path(path)
    if not path.is_file():
        raise UnsupportedFile(f"ファイルが見つかりません: {path}")
    suffix = path.suffix.lower()
    if suffix in DOCX_SUFFIXES:
        return mask_docx_file(path, vault, output)
    if suffix in PDF_SUFFIXES:
        return mask_pdf_file(path, vault, output, mode=pdf_mode)
    if suffix in TEXT_SUFFIXES or suffix == "":
        return mask_text_file(path, vault, output)
    raise UnsupportedFile(f"未対応の形式です: {path.suffix or path.name}")


def read_any(path: Path) -> str:
    """マスクせずにテキストだけ取り出す（検出プレビュー用）。"""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in PDF_SUFFIXES:
        return extract_pdf_text(path)
    if suffix in DOCX_SUFFIXES:
        import docx  # type: ignore

        document = docx.Document(str(path))
        parts = [p.text for p in _iter_docx_paragraphs(document)]
        for section in document.sections:
            for area in (section.header, section.footer):
                if area is not None:
                    parts.extend(p.text for p in _iter_docx_paragraphs(area))
        return "\n".join(parts)
    return read_text_file(path)[0]
