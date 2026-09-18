"""検出結果をプレースホルダに置き換える／元に戻す。"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Sequence

from .detectors import CATEGORIES, DEFAULT_CATEGORIES, Detection, detect


@dataclass
class MaskConfig:
    categories: Sequence[str] = DEFAULT_CATEGORIES
    custom_terms: Sequence[tuple[str, str]] = ()
    all_dates: bool = False
    url_mode: str = "domain"      # "domain" = ドメインだけ / "full" = URL 全体
    org_guess: bool = True        # 法人格の無い社名も業種語から推測する
    domain_allowlist: Sequence[str] | None = None
    redact: bool = False          # True なら復元不能な伏字にする
    redact_char: str = "●"
    placeholder_format: str = "[{label}_{index}]"


@dataclass
class MaskResult:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)
    hits: list[dict] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.hits)

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for hit in self.hits:
            out[hit["display"]] = out.get(hit["display"], 0) + 1
        return out


class Vault:
    """1回のマスク処理をまたいでプレースホルダの一貫性を保つ台帳。

    複数ファイルを同じ Vault で処理すれば、同じ「山田太郎」は
    どのファイルでも同じ [人名_1] になる。
    """

    def __init__(self, config: MaskConfig | None = None) -> None:
        self.config = config or MaskConfig()
        self.mapping: dict[str, str] = {}      # placeholder -> original
        self._by_value: dict[tuple[str, str, str], str] = {}
        self._counters: dict[str, int] = {}
        self._alias_counters: dict[str, int] = {}

    # --- 台帳操作 -------------------------------------------------
    @staticmethod
    def _normalize(value: str) -> str:
        return unicodedata.normalize("NFKC", value).strip().lower()

    def placeholder_for(self, category: str, value: str, label: str | None = None) -> str:
        display = label or CATEGORIES[category][0]
        key = (category, display, self._normalize(value))
        if key in self._by_value:
            return self._by_value[key]
        self._counters[display] = self._counters.get(display, 0) + 1
        placeholder = self.config.placeholder_format.format(
            label=display, index=self._counters[display]
        )
        self._by_value[key] = placeholder
        self.mapping[placeholder] = value
        return placeholder

    def alias_placeholder_for(
        self, parent: str, category: str, value: str, label: str | None = None
    ) -> str:
        """本体と同じ人物だと分かるよう、枝番付きのプレースホルダを割り当てる。

        [人名_1] の読み仮名なら [人名_1a]。復元はそれぞれ個別に行われる。
        """
        display = label or CATEGORIES[category][0]
        key = (category, display, self._normalize(value))
        if key in self._by_value:
            return self._by_value[key]
        index = self._alias_counters.get(parent, 0)
        self._alias_counters[parent] = index + 1
        suffix = chr(ord("a") + index) if index < 26 else f"a{index}"
        placeholder = f"{parent[:-1]}{suffix}]"
        self._by_value[key] = placeholder
        self.mapping[placeholder] = value
        return placeholder

    def load_mapping(self, mapping: dict[str, str]) -> None:
        """既存のマッピングを取り込み、続きの番号から採番する。"""
        for placeholder, original in mapping.items():
            if placeholder in self.mapping:
                continue
            self.mapping[placeholder] = original
            m = re.match(
                r"\[(?P<label>[^\]_]+)_(?P<index>\d+)(?P<alias>[a-z]*\d*)\]$", placeholder
            )
            if m:
                label, index = m.group("label"), int(m.group("index"))
                if not m.group("alias"):
                    self._counters[label] = max(self._counters.get(label, 0), index)
                category = next(
                    (c for c, (d, _) in CATEGORIES.items() if d == label), "USER"
                )
                self._by_value.setdefault(
                    (category, label, self._normalize(original)), placeholder
                )

    # --- マスク ---------------------------------------------------
    def mask(self, text: str) -> MaskResult:
        if not text:
            return MaskResult(text="")
        detections = detect(
            text,
            categories=self.config.categories,
            custom_terms=self.config.custom_terms,
            all_dates=self.config.all_dates,
            url_mode=self.config.url_mode,
            domain_allowlist=self.config.domain_allowlist,
            org_guess=self.config.org_guess,
        )
        return self._apply(text, detections)

    def _apply(self, text: str, detections: list[Detection]) -> MaskResult:
        out: list[str] = []
        hits: list[dict] = []
        cursor = 0
        for det in detections:
            out.append(text[cursor:det.start])
            if det.category == "KEEP":      # URL のパスなど、意図的に残す領域
                out.append(det.value)
                cursor = det.end
                continue
            if self.config.redact:
                replacement = self.config.redact_char * max(1, len(det.value))
            elif det.alias_of:
                parent = self.placeholder_for(det.category, det.alias_of, det.label)
                replacement = self.alias_placeholder_for(
                    parent, det.category, det.value, det.label
                )
            else:
                replacement = self.placeholder_for(det.category, det.value, det.label)
            out.append(replacement)
            hits.append(
                {
                    "category": det.category,
                    "display": det.display,
                    "value": det.value,
                    "replacement": replacement,
                    "rule": det.rule,
                    "start": det.start,
                    "end": det.end,
                }
            )
            cursor = det.end
        out.append(text[cursor:])
        return MaskResult(text="".join(out), mapping=dict(self.mapping), hits=hits)


def mask_text(text: str, config: MaskConfig | None = None) -> MaskResult:
    """単発のテキストをマスクする簡易関数。"""
    return Vault(config).mask(text)


def restore_text(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    """プレースホルダを元の値に戻す。戻した件数も返す。"""
    if not mapping:
        return text, 0
    # 長いプレースホルダから置換して部分一致事故を避ける
    ordered = sorted(mapping.items(), key=lambda kv: len(kv[0]), reverse=True)
    count = 0
    for placeholder, original in ordered:
        occurrences = text.count(placeholder)
        if occurrences:
            text = text.replace(placeholder, original)
            count += occurrences
    return text, count


def leftover_placeholders(text: str) -> list[str]:
    """マッピングに無いのに残っているプレースホルダを探す。"""
    return sorted(set(re.findall(r"\[[^\]\s]+_\d+[a-z]*\d*\]", text)))
