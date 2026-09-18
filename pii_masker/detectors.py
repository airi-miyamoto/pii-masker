"""個人情報の検出ルール。

すべて正規表現＋辞書によるルールベース。外部通信もモデルロードも行わない。
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Sequence

from .lexicon import (
    ADDRESS_LABELS,
    CORP_ABBREVIATIONS,
    ORG_HONORIFICS,
    ORG_SUFFIXES_STRONG,
    ORG_SUFFIXES_WEAK,
    DEFAULT_DOMAIN_ALLOWLIST,
    KNOWN_TLDS,
    NOT_GIVEN_NAMES,
    CORP_PREFIXES,
    CORP_SUFFIXES,
    HONORIFICS,
    NAME_LABELS,
    NAME_STOPWORDS,
    PREFECTURES,
    SURNAMES_MULTI,
    SURNAMES_SINGLE,
    TITLES,
)

# ラベル -> (日本語表示名, 優先度)。優先度が高いルールが重複範囲を勝ち取る。
CATEGORIES: dict[str, tuple[str, int]] = {
    "KEEP": ("保護", 101),
    "USER": ("機密語", 100),
    "EMAIL": ("メール", 90),
    "URL": ("URL", 85),
    "IP": ("IPアドレス", 80),
    "MYNUMBER": ("マイナンバー", 78),
    "CARD": ("カード番号", 76),
    "BANK": ("口座番号", 74),
    "ZIP": ("郵便番号", 72),
    "PHONE": ("電話番号", 70),
    "ADDRESS": ("住所", 60),
    "BIRTH": ("生年月日", 55),
    "ORG": ("組織名", 50),
    "NAME": ("人名", 40),
}

# KEEP は内部用なので、利用者が選ぶカテゴリからは外す
DEFAULT_CATEGORIES = tuple(c for c in CATEGORIES if c != "KEEP")


@dataclass(frozen=True)
class Detection:
    start: int
    end: int
    category: str
    value: str
    rule: str
    label: str | None = None
    alias_of: str | None = None   # 「/ yamada」のような別名が指す本体の値

    @property
    def display(self) -> str:
        return self.label or CATEGORIES[self.category][0]

    @property
    def priority(self) -> int:
        return CATEGORIES[self.category][1]


def _alt(items: Iterable[str]) -> str:
    """正規表現の選択肢を長い順に並べて生成する（最長一致のため）。"""
    return "|".join(re.escape(s) for s in sorted(set(items), key=len, reverse=True))


_HON = _alt(HONORIFICS)
_TIT = _alt(TITLES)
_SUR_M = _alt(SURNAMES_MULTI)
_SUR_S = _alt(SURNAMES_SINGLE)
_PREF = _alt(PREFECTURES)
_SP = r"[ 　\t]"
# 「山田\t営業部」のように、名の位置に部署名が来たら人名ではない
DEPT_TAIL_RE = re.compile(r"(?:部|課|室|係|科|局|団|署|本部|支部|支店|営業所|"
                         r"チーム|グループ|センター|事業部|事業所)$")
# 名の各文字は敬称の開始位置であってはならない（「佐々木さんと林」のような誤結合を防ぐ）
_GIVEN_CHAR = r"[一-龥々ヶぁ-んァ-ヶー]"
_GIVEN = rf"(?:(?!{_HON}){_GIVEN_CHAR}){{1,4}}"

# 人名の直後に現れてよい文字（助詞・句読点・括弧・記号・行末）
_NAME_BOUNDARY = (
    r"(?:が|は|を|に|へ|と|の|も|で|や|から|まで|より|さ|です|でした|宛)"
    r"|[\s、。，．,\.　()（）\[\]【】「」『』〈〉<>：:;；/／|｜\\\-–—＆&＠@+*!?！？~〜=•・]"
    r"|$"
)

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}"
)
URL_RE = re.compile(r"(?:https?://|ftp://|www\.)[^\s<>\"'「」『』（）()【】\[\]、。，]+")
# ドメインに続くパス部分（? の手前まで）。クエリの値は検査対象に残す
URL_PATH_RE = re.compile(r"/[^\s<>\"'「」『』（）()【】\[\]、。，?]*")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# スキームの付かない「example.co.jp」形式。既知 TLD に限定してファイル名との衝突を避ける
_TLD_ALT = "|".join(re.escape(t) for t in sorted(KNOWN_TLDS, key=len, reverse=True))
BARE_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9@.\-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    rf"(?:{_TLD_ALT})(?![A-Za-z0-9\-])",
    re.IGNORECASE,
)
ZIP_RE = re.compile(
    r"〒\s?\d{3}[-‐−ー－ｰ]?\d{4}(?![\d\-‐−ー－ｰ])"
    r"|(?<![\d\-‐−ー－ｰ])\d{3}[-‐−ー－ｰ]\d{4}(?![\d\-‐−ー－ｰ])"
)
PHONE_RE = re.compile(r"(?<![0-9\-])(?:\+81[ \-]?|0)[0-9][0-9\-() 　]{7,14}[0-9](?![0-9])")
# 4 桁ずつ区切られた形式。これ単体で十分に確度が高い
CARD_SPACED_RE = re.compile(r"(?<![\d\-])\d{4}[ \-]\d{4}[ \-]\d{4}[ \-]\d{1,4}(?![\d\-])")
# 区切りの無い連番。注文番号や管理番号と区別できないので文脈語を必須にする
CARD_PLAIN_RE = re.compile(r"(?<![\d\-])\d{13,16}(?![\d\-])")
CARD_CONTEXT_RE = re.compile(
    r"カード|クレジット|クレカ|デビット|決済|与信|PAN|VISA|Visa|MasterCard|Mastercard"
    r"|JCB|AMEX|Amex|American\s?Express|Diners|Discover|銀聯|card|Card|CARD"
)
MYNUMBER_RE = re.compile(
    r"(?:マイナンバー|個人番号|マイナンバーカード)[^\d\n]{0,12}"
    r"((?<!\d)\d{4}[ \-]?\d{4}[ \-]?\d{4}(?!\d))"
)
BANK_RE = re.compile(
    r"(?:口座番号|口座|普通|当座|貯蓄|預金)[^\d\n]{0,10}((?<!\d)\d{7}(?!\d))"
)

_BIRTH_LABEL = r"(?:生年月日|誕生日|生年|birth\s?date|date\s?of\s?birth|DOB|Birthday)"
_DATE_WAREKI = r"(?:明治|大正|昭和|平成|令和)\s?\d{1,2}\s?年\s?\d{1,2}\s?月\s?\d{1,2}\s?日"
_DATE_SEIREKI = r"(?<!\d)(?:1[89]|20)\d{2}\s?[年/\-\.]\s?\d{1,2}\s?[月/\-\.]\s?\d{1,2}\s?日?(?!\d)"
BIRTH_LABELED_RE = re.compile(
    rf"{_BIRTH_LABEL}[^\d明大昭平令\n]{{0,10}}({_DATE_WAREKI}|{_DATE_SEIREKI})",
    re.IGNORECASE,
)
BIRTH_WAREKI_RE = re.compile(_DATE_WAREKI)
ANY_DATE_RE = re.compile(rf"{_DATE_WAREKI}|{_DATE_SEIREKI}")

_CITY = r"(?:[一-龥ぁ-んァ-ヶー々]{1,8}?[市区町村郡]){1,3}"
_TOWN = (
    r"(?:[一-龥ぁ-んァ-ヶーA-Za-z0-9０-９々]{1,12}?(?:丁目|番町|大字|字|条|町|村)"
    r"|[一-龥ァ-ヶー々]{1,10}?)?"
)
_BANCHI = r"[0-9０-９]+(?:[ 　]?(?:丁目|番地|番|号|[-‐−ー－ｰ])[ 　]?[0-9０-９]*)*"
_BLDG = (
    r"(?:[ 　]?[^\s、。\n]{1,24}?"
    r"(?:ビル|ビルディング|マンション|ハイツ|コーポ|荘|タワー|ハウス|レジデンス|パレス"
    r"|棟|号室|号館)(?:[ 　]?[0-9０-９]{1,4}\s?(?:階|F|Ｆ|号室|号))?)?"
)
ADDRESS_PREF_RE = re.compile(rf"(?:{_PREF}){_CITY}{_TOWN}{_BANCHI}{_BLDG}")
ADDRESS_LABELED_RE = re.compile(
    rf"(?:{_alt(ADDRESS_LABELS)})[ 　]*[:：][ 　]*([^\n]{{4,80}}?)(?=\s*$|\s*[、。\n])",
    re.MULTILINE,
)
# 郵便番号の直後に続く住所（都道府県が省略されていても拾う）
ADDRESS_AFTER_ZIP_RE = re.compile(
    rf"(?:〒\s?\d{{3}}[-‐−ー－ｰ]?\d{{4}}|(?<!\d)\d{{3}}[-‐−ー－ｰ]\d{{4}})[ 　]*"
    rf"((?:{_PREF})?{_CITY}{_TOWN}{_BANCHI}{_BLDG})"
)

_CORP_BODY = r"[一-龥ぁ-んァ-ヶーA-Za-z0-9０-９・＆&'’\.]"
# 社名の終わりと判断してよい位置（助詞・記号・敬称・行末）
_ORG_BOUNDARY = (
    r"(?:の|は|が|を|に|へ|と|も|や|から|まで|より|様|御中|殿|宛|にて|では)"
    r"|[\s、。，．,\.()（）「」『』【】\[\]:：;；/／|｜\\\-–—]|$"
)
ORG_PREFIX_RE = re.compile(
    rf"(?:{_alt(CORP_PREFIXES)})[ 　]?{_CORP_BODY}{{1,24}}?(?={_ORG_BOUNDARY})"
)
ORG_SUFFIX_RE = re.compile(rf"{_CORP_BODY}{{1,24}}[ 　]?(?:{_alt(CORP_SUFFIXES)})")
# (株) ㈱ (有) といった略記。実務の書類では正式名称より頻出する
ORG_ABBREV_PREFIX_RE = re.compile(
    rf"(?:{_alt(CORP_ABBREVIATIONS)})[ 　]?{_CORP_BODY}{{1,24}}?(?={_ORG_BOUNDARY})"
)
ORG_ABBREV_SUFFIX_RE = re.compile(
    rf"{_CORP_BODY}{{1,24}}[ 　]?(?:{_alt(CORP_ABBREVIATIONS)})"
)
# 「御中」は組織にしか使わないので、直前は高い確度で組織名
_ORG_NAME_BODY = r"[一-龥ぁ-んァ-ヶーA-Za-z0-9０-９・＆&'’\.\(\)（）㈱㈲]"
ORG_ONCHU_RE = re.compile(
    rf"({_ORG_NAME_BODY}{{2,30}})[ 　]*(?:{_alt(ORG_HONORIFICS)})"
)
# 法人格が無くても組織とみなせる語（工務店・商店・クリニックなど）
ORG_INDUSTRY_STRONG_RE = re.compile(
    rf"({_ORG_NAME_BODY}{{1,20}}?(?:{_alt(ORG_SUFFIXES_STRONG)}))(?={_ORG_BOUNDARY})"
)
# 一般名詞にもなる業種語。org_guess=True のときだけ使う
ORG_INDUSTRY_WEAK_RE = re.compile(
    rf"({_ORG_NAME_BODY}{{1,20}}?(?:{_alt(ORG_SUFFIXES_WEAK)}))(?={_ORG_BOUNDARY})"
)
# 「取引先はトヨタ自動車株式会社」のように直前の語を巻き込んだ場合に切り落とす
ORG_LEADING_PARTICLE_RE = re.compile(r"^.*?[はがをにへとも](?=[一-龥ァ-ヶA-Za-z])")
# 「弊社の設計事務所」の「弊社の」のように、組織名の手前に付く語
ORG_LEAD_STOPWORDS = (
    "弊社", "当社", "御社", "貴社", "自社", "他社", "同社", "各社", "先方",
    "本社", "支社", "当該", "上記", "下記", "取引先", "クライアント",
)
_ORG_TAIL_WORDS = (
    set(CORP_PREFIXES) | set(CORP_SUFFIXES) | set(CORP_ABBREVIATIONS)
    | set(ORG_SUFFIXES_STRONG) | set(ORG_SUFFIXES_WEAK)
)


def _trim_name_lead(text: str, start: int, end: int) -> int:
    """「ご担当 山田太郎」の「担当」のように、人名の手前に付く語を取り除く。"""
    words = sorted(NAME_STOPWORDS, key=len, reverse=True)
    while True:
        value = text[start:end]
        for word in words:
            if value.startswith(word) and len(value) > len(word):
                rest = value[len(word):].lstrip(" 　・:：")
                if rest:
                    start = end - len(rest)
                    break
        else:
            return start


def _trim_org_lead(text: str, start: int, end: int) -> int:
    """組織名の手前に紛れ込んだ助詞や「弊社の」を取り除く。"""
    while True:
        value = text[start:end]
        cut = ORG_LEADING_PARTICLE_RE.match(value)
        if cut:
            start += cut.end()
            continue
        for word in ORG_LEAD_STOPWORDS:
            if value.startswith(word):
                skip = len(word)
                if value[skip:skip + 1] == "の":
                    skip += 1
                if skip < len(value):
                    start += skip
                    break
        else:
            return start
ORG_EN_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9&\.'\- ]{1,40}?"
    r"(?:Inc\.|Incorporated|Corp\.|Corporation|Co\.,?[ ]?Ltd\.?|Company|LLC|LLP|GmbH|S\.A\.|B\.V\.|Pty\.?[ ]?Ltd\.?)"
)

NAME_FULL_HON_RE = re.compile(
    rf"(?<![一-龥々])((?:{_SUR_M}){_SP}{{0,3}}(?P<given>{_GIVEN}))(?=(?:{_HON}|{_TIT}))"
)
NAME_SUR_HON_RE = re.compile(rf"(?<![一-龥々])((?:{_SUR_M}|{_SUR_S}))(?=(?:{_HON}|{_TIT}))")
NAME_FULL_SPACED_RE = re.compile(
    rf"(?<![一-龥々])((?:{_SUR_M}){_SP}{{1,3}}(?P<given>{_GIVEN}))(?={_NAME_BOUNDARY})"
)
NAME_SUR_ONLY_RE = re.compile(rf"(?<![一-龥々])((?:{_SUR_M}))(?={_NAME_BOUNDARY})")
# 敬称も区切りも無い「山田太郎」形式（CSV や名簿でよく出る）
# 名の 1 文字ごとに敬称・肩書の開始でないことを確認する
# （そうしないと「山田太郎様」の「様」まで名に含めてしまう）
_NOT_SUFFIX = rf"(?!{_HON}|{_TIT})"
_GIVEN_PLAIN = (
    rf"(?:(?:{_NOT_SUFFIX}[一-龥々]){{1,3}}"
    rf"|(?:{_NOT_SUFFIX}[ぁ-ん]){{2,4}}"
    rf"|(?:{_NOT_SUFFIX}[ァ-ヶー]){{2,4}})"
)
NAME_FULL_PLAIN_RE = re.compile(
    rf"(?<![一-龥々])((?:{_SUR_M})(?P<given>{_GIVEN_PLAIN}))(?={_NAME_BOUNDARY})"
)
NAME_UNKNOWN_HON_RE = re.compile(
    rf"(?<![一-龥々])([一-龥々]{{1,4}}(?:{_SP}{{1,3}}[一-龥々ぁ-んァ-ヶー]{{1,4}})?)(?=(?:{_HON}|{_TIT}))"
)
NAME_LABELED_RE = re.compile(
    rf"(?:{_alt(NAME_LABELS)})[ 　]*[:：][ 　]*([^\s、。\n]{{2,16}})"
)
# Slack の表示名「山田 太郎 / やまだ / yamada」のように、
# 区切り文字で読み仮名やローマ字が並ぶ形式を丸ごと 1 人分として扱う
_ALIAS_SEP = r"[ 　\t]*[/／|｜･・][ 　\t]*"
# 読み仮名・ローマ字はフルネームで書かれることもある（「やまだ たろう」）
_ALIAS_KANA_WORD = r"[ぁ-んァ-ヶーｦ-ﾟ]{2,12}"
_ALIAS_KANA = rf"{_ALIAS_KANA_WORD}(?:{_SP}{{1,3}}{_ALIAS_KANA_WORD}){{0,2}}"
_ALIAS_ROMAJI_WORD = r"[A-Za-z][A-Za-z'\.]{1,19}"
_ALIAS_ROMAJI = (
    rf"{_ALIAS_ROMAJI_WORD}(?:[ \-_]{{1,3}}[A-Za-z][A-Za-z'\.]{{0,19}}){{0,2}}"
)
ALIAS_WORD_SPLIT_RE = re.compile(r"[ 　\t\-_]+")
# 「山田 太郎 / https://...」の https を別名にしないため
ALIAS_EXCLUDED_WORDS = {"https", "http", "ftp", "www", "mailto", "tel", "sms", "file"}
NAME_ALIAS_ONE_RE = re.compile(rf"{_ALIAS_SEP}({_ALIAS_KANA}|{_ALIAS_ROMAJI})")
# 別名を取り込んでよいのは、敬称の付かない「表示名らしい」書き方のときだけ。
# 「山田さん / お疲れ様です」のようなチャットの文を巻き込まないため。
ALIAS_BASE_RULES = ("name:full-spaced", "name:full-plain", "name:label", "name:kana")
ALIAS_SPLIT_RE = re.compile(r"[/／|｜･・]")

NAME_KANA_RE = re.compile(
    r"(?<![ァ-ヶー])([ァ-ヶ][ァ-ヶー]{1,7}[ 　\t・]{1,3}[ァ-ヶ][ァ-ヶー]{1,7})(?![ァ-ヶー])"
)


def url_host_span(url: str, offset: int) -> tuple[int, int, str] | None:
    """URL 文字列からホスト部分の範囲を取り出す。"""
    scheme = re.match(r"(?:https?|ftp)://", url)
    start = scheme.end() if scheme else 0
    host = re.match(r"[^/\s:?#@]+", url[start:])
    if not host:
        return None
    return offset + start, offset + start + host.end(), host.group(0)


def domain_allowed(host: str, allowlist) -> bool:
    """マスク対象外のドメインか判定する（サブドメインも含めて一致を見る）。"""
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowlist)


def _line_at(text: str, pos: int) -> str:
    """指定位置を含む 1 行を返す（文脈語の有無を見るために使う）。"""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start:end if end >= 0 else len(text)]


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _digits(s: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKC", s) if ch.isdigit())


def _valid_phone(raw: str) -> bool:
    d = _digits(raw.replace("+81", "0", 1) if raw.startswith("+81") else raw)
    if not d.startswith("0"):
        return False
    if len(d) not in (10, 11):
        return False
    # 市外局番/事業者番号として妥当な先頭
    return d[1] != "0" or d.startswith("00")


def _valid_ip(raw: str) -> bool:
    parts = [int(part) for part in raw.split(".")]
    if any(part > 255 for part in parts):
        return False
    first, second = parts[0], parts[1]
    # ループバック・プライベート・リンクローカルは個人情報ではないので残す
    if first in (0, 10, 127) or parts == [255, 255, 255, 255]:
        return False
    if first == 192 and second == 168:
        return False
    if first == 172 and 16 <= second <= 31:
        return False
    if first == 169 and second == 254:
        return False
    return True


def _add(
    out: list[Detection], category: str, start: int, end: int, text: str, rule: str,
    label: str | None = None,
) -> None:
    value = text[start:end]
    stripped = value.rstrip(" 　\t")
    end -= len(value) - len(stripped)
    value = stripped
    if value:
        out.append(Detection(start, end, category, value, rule, label))


def _scan_custom(text: str, terms: Sequence[tuple[str, str]], out: list[Detection]) -> None:
    for term, label in terms:
        term = term.strip()
        if not term:
            continue
        for m in re.finditer(re.escape(term), text):
            out.append(Detection(m.start(), m.end(), "USER", m.group(0), f"custom:{label}"))


DOMAIN_LABEL = "ドメイン"


def detect(
    text: str,
    *,
    categories: Sequence[str] = DEFAULT_CATEGORIES,
    custom_terms: Sequence[tuple[str, str]] = (),
    all_dates: bool = False,
    url_mode: str = "domain",
    domain_allowlist: Sequence[str] | None = None,
    org_guess: bool = True,
) -> list[Detection]:
    """テキストから個人情報候補を検出し、重複を解決して返す。

    url_mode="domain" ならドメイン部分だけを対象にし、パスやクエリは残す。
    url_mode="full" なら URL 全体を 1 つの値として置き換える。
    """
    enabled = set(categories)
    allowlist = (DEFAULT_DOMAIN_ALLOWLIST if domain_allowlist is None
                 else {d.lower() for d in domain_allowlist})
    raw: list[Detection] = []

    if custom_terms:
        _scan_custom(text, custom_terms, raw)

    if "EMAIL" in enabled:
        for m in EMAIL_RE.finditer(text):
            _add(raw, "EMAIL", m.start(), m.end(), text, "email")
    if "URL" in enabled:
        if url_mode == "full":
            for m in URL_RE.finditer(text):
                span = url_host_span(m.group(0), m.start())
                if span and domain_allowed(span[2], allowlist):
                    continue      # 除外ドメインは URL 全体モードでもマスクしない
                _add(raw, "URL", m.start(), m.end(), text, "url:full")
        else:
            for m in URL_RE.finditer(text):
                span = url_host_span(m.group(0), m.start())
                if not span:
                    continue
                host_start, host_end, host = span
                if not domain_allowed(host, allowlist):
                    _add(raw, "URL", host_start, host_end, text, "url:domain", DOMAIN_LABEL)
                # パス（スラッグ）はそのまま共有したいので保護する。
                # ただし ?id=... 以降は値が入りうるので検査対象に残す。
                rest = text[host_end:m.end()]
                path_end = host_end + (len(rest) if "?" not in rest else rest.index("?"))
                if path_end > host_end:
                    _add(raw, "KEEP", host_end, path_end, text, "url:path")
        for m in BARE_DOMAIN_RE.finditer(text):
            if domain_allowed(m.group(0), allowlist):
                continue
            path = URL_PATH_RE.match(text, m.end())
            has_path = bool(path) and path.end() > m.end()
            if url_mode == "full" and has_path:
                # スキームが無くても URL 全体を 1 つとして置き換える
                _add(raw, "URL", m.start(), path.end(), text, "domain:bare-full")
                continue
            _add(raw, "URL", m.start(), m.end(), text, "domain:bare", DOMAIN_LABEL)
            # example.co.jp/works/detail/ のようにスキームが無くてもパスは保護する
            if has_path:
                _add(raw, "KEEP", m.end(), path.end(), text, "domain:path")
    if "IP" in enabled:
        for m in IP_RE.finditer(text):
            if _valid_ip(m.group(0)):
                _add(raw, "IP", m.start(), m.end(), text, "ip")
    if "MYNUMBER" in enabled:
        for m in MYNUMBER_RE.finditer(text):
            _add(raw, "MYNUMBER", m.start(1), m.end(1), text, "mynumber")
    if "CARD" in enabled:
        for m in CARD_SPACED_RE.finditer(text):
            d = _digits(m.group(0))
            if 13 <= len(d) <= 16 and _luhn_ok(d):
                _add(raw, "CARD", m.start(), m.end(), text, "card:spaced")
        for m in CARD_PLAIN_RE.finditer(text):
            d = m.group(0)
            if _luhn_ok(d) and CARD_CONTEXT_RE.search(_line_at(text, m.start())):
                _add(raw, "CARD", m.start(), m.end(), text, "card:context")
    if "BANK" in enabled:
        for m in BANK_RE.finditer(text):
            _add(raw, "BANK", m.start(1), m.end(1), text, "bank")
    if "ZIP" in enabled:
        for m in ZIP_RE.finditer(text):
            _add(raw, "ZIP", m.start(), m.end(), text, "zip")
    if "PHONE" in enabled:
        for m in PHONE_RE.finditer(text):
            if _valid_phone(m.group(0)):
                _add(raw, "PHONE", m.start(), m.end(), text, "phone")
    if "ADDRESS" in enabled:
        for m in ADDRESS_PREF_RE.finditer(text):
            _add(raw, "ADDRESS", m.start(), m.end(), text, "address:pref")
        for m in ADDRESS_AFTER_ZIP_RE.finditer(text):
            _add(raw, "ADDRESS", m.start(1), m.end(1), text, "address:zip")
        for m in ADDRESS_LABELED_RE.finditer(text):
            _add(raw, "ADDRESS", m.start(1), m.end(1), text, "address:label")
    if "BIRTH" in enabled:
        if all_dates:
            for m in ANY_DATE_RE.finditer(text):
                _add(raw, "BIRTH", m.start(), m.end(), text, "date:any")
        else:
            for m in BIRTH_LABELED_RE.finditer(text):
                _add(raw, "BIRTH", m.start(1), m.end(1), text, "birth:label")
            for m in BIRTH_WAREKI_RE.finditer(text):
                _add(raw, "BIRTH", m.start(), m.end(), text, "birth:wareki")
    if "ORG" in enabled:
        for regex, rule in ((ORG_PREFIX_RE, "org:prefix"),
                            (ORG_ABBREV_PREFIX_RE, "org:abbrev")):
            for m in regex.finditer(text):
                _add(raw, "ORG", m.start(), m.end(), text, rule)
        for regex, rule in ((ORG_SUFFIX_RE, "org:suffix"),
                            (ORG_ABBREV_SUFFIX_RE, "org:abbrev-suffix")):
            for m in regex.finditer(text):
                _add(raw, "ORG", _trim_org_lead(text, m.start(), m.end()),
                     m.end(), text, rule)
        for m in ORG_EN_RE.finditer(text):
            _add(raw, "ORG", m.start(), m.end(), text, "org:en")
        industry_rules = [(ORG_ONCHU_RE, "org:onchu"),
                          (ORG_INDUSTRY_STRONG_RE, "org:industry")]
        if org_guess:
            industry_rules.append((ORG_INDUSTRY_WEAK_RE, "org:industry-guess"))
        for regex, rule in industry_rules:
            for m in regex.finditer(text):
                start = _trim_org_lead(text, m.start(1), m.end(1))
                value = text[start:m.end(1)]
                # 「弊社の設計事務所」のように業種語だけが残った場合は組織名ではない
                if len(value) >= 2 and value not in _ORG_TAIL_WORDS:
                    _add(raw, "ORG", start, m.end(1), text, rule)
    if "NAME" in enabled:
        for regex, rule in (
            (NAME_LABELED_RE, "name:label"),
            (NAME_FULL_HON_RE, "name:full+hon"),
            (NAME_SUR_HON_RE, "name:sur+hon"),
            (NAME_UNKNOWN_HON_RE, "name:unknown+hon"),
            (NAME_FULL_SPACED_RE, "name:full-spaced"),
            (NAME_FULL_PLAIN_RE, "name:full-plain"),
            (NAME_SUR_ONLY_RE, "name:sur"),
            (NAME_KANA_RE, "name:kana"),
        ):
            for m in regex.finditer(text):
                value = m.group(1)
                if value in NAME_STOPWORDS or value.strip() in NAME_STOPWORDS:
                    continue
                if any(value.startswith(p) or value.endswith(p) for p in CORP_PREFIXES):
                    continue
                if any(value.endswith(w) for w in _ORG_TAIL_WORDS):
                    continue
                given = m.groupdict().get("given")
                if given and (given in NOT_GIVEN_NAMES or DEPT_TAIL_RE.search(given)):
                    continue
                start = _trim_name_lead(text, m.start(1), m.end(1))
                if text[start:m.end(1)] in NAME_STOPWORDS:
                    continue
                _add(raw, "NAME", start, m.end(1), text, rule)

    if "NAME" in enabled:
        _expand_name_aliases(text, raw)

    return _resolve(raw)


def _expand_name_aliases(text: str, raw: list[Detection]) -> None:
    """人名の直後に続く「/ やまだ / yamada」を人名の一部として取り込む。

    取り込んだ読み仮名やローマ字が文書の別の場所に単独で出てきた場合も、
    同じ人物として検出する。
    """
    # メールアドレスや URL と重なる位置までは伸ばさない。
    # 「山田 太郎 / やまだ / yamada@example.co.jp」で本体ごと消えてしまうため。
    blockers = [d for d in raw if d.priority > CATEGORIES["NAME"][1]]
    extended: list[Detection] = []
    for det in list(raw):
        if det.category != "NAME" or det.rule not in ALIAS_BASE_RULES:
            continue
        end = det.end
        while True:
            # メールや URL の手前までを探索範囲にする
            limit = min((b.start for b in blockers if b.start >= end), default=len(text))
            m = NAME_ALIAS_ONE_RE.match(text, end, limit)
            if not m:
                break
            part = m.group(1)
            # URL やメールの一部を別名として取り込まない
            if part.lower() in ALIAS_EXCLUDED_WORDS or text[m.end():m.end() + 1] in (":", "@"):
                break
            words = ALIAS_WORD_SPLIT_RE.split(part)
            if any(w in NOT_GIVEN_NAMES or w in NAME_STOPWORDS for w in words):
                break
            end = m.end()
        if end > det.end:
            extended.append(Detection(
                det.start, end, "NAME", text[det.start:end],
                det.rule + "+alias", det.label,
            ))
    if not extended:
        return
    raw.extend(extended)

    aliases: dict[str, str] = {}
    for det in extended:
        for part in ALIAS_SPLIT_RE.split(det.value):
            part = part.strip()
            # 2 文字以下は一般語と衝突しやすいので横展開しない
            if len(part) >= 3:
                aliases.setdefault(part, det.value)
            if part.isascii() and any(c.isalpha() for c in part):
                for word in ALIAS_WORD_SPLIT_RE.split(part):
                    if len(word) >= 4 and word.isalpha():
                        aliases.setdefault(word, det.value)
    for alias, parent in aliases.items():
        for m in re.finditer(re.escape(alias), text):
            raw.append(Detection(m.start(), m.end(), "NAME", alias,
                                 "name:alias-ref", None, parent))


def _resolve(items: list[Detection]) -> list[Detection]:
    """重複する検出を優先度 → 長さ → 出現位置の順で解決する。"""
    items.sort(key=lambda d: (-d.priority, -(d.end - d.start), d.start))
    chosen: list[Detection] = []
    for det in items:
        if any(det.start < c.end and c.start < det.end for c in chosen):
            continue
        chosen.append(det)
    chosen.sort(key=lambda d: d.start)
    return chosen
