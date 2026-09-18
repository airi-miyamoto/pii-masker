"""pii-masker のテスト: python3 -m unittest discover -s tests"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pii_masker.detectors import detect
from pii_masker.masker import MaskConfig, Vault, mask_text, restore_text


def categories(text, **kwargs):
    return {d.category for d in detect(text, **kwargs)}


def values(text, category, **kwargs):
    return [d.value for d in detect(text, **kwargs) if d.category == category]


class TestDetect(unittest.TestCase):
    def test_email(self):
        self.assertEqual(values("連絡は taro.yamada@example.co.jp まで", "EMAIL"),
                         ["taro.yamada@example.co.jp"])

    def test_phone_variants(self):
        for raw in ("052-123-4567", "090-1234-5678", "0120-123-456", "09012345678"):
            with self.subTest(raw=raw):
                self.assertIn(raw, values(f"電話 {raw} です", "PHONE"))

    def test_phone_not_confused_with_zip(self):
        found = values("〒460-0008 TEL 052-123-4567", "PHONE")
        self.assertEqual(found, ["052-123-4567"])

    def test_zip(self):
        self.assertEqual(values("〒460-0008 愛知県", "ZIP"), ["〒460-0008"])

    def test_address(self):
        self.assertEqual(values("愛知県名古屋市中区栄3-15-33 いちご栄ビル5Fです", "ADDRESS"),
                         ["愛知県名古屋市中区栄3-15-33 いちご栄ビル5F"])

    def test_card_luhn(self):
        self.assertEqual(values("card 4111 1111 1111 1111", "CARD"), ["4111 1111 1111 1111"])
        # Luhn が通らない番号は検出しない
        self.assertEqual(values("id 4111 1111 1111 1112", "CARD"), [])

    def test_card_plain_digits_need_context(self):
        # 注文番号や管理番号が Luhn を偶然通ってもカード番号にしない
        self.assertEqual(values("注文番号 4539578763621486 を確認", "CARD"), [])
        self.assertEqual(values("管理番号: 4539578763621486", "CARD"), [])
        self.assertEqual(values("カード番号 4539578763621486", "CARD"),
                         ["4539578763621486"])

    def test_card_not_detected_inside_url(self):
        for raw in ("https://example.co.jp/track/4111111111111111/",
                    "example.co.jp/track/4111111111111111/",
                    "cdn.example.co.jp/assets/4539578763621486.png"):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "CARD"), [])

    def test_bare_domain_path_is_protected(self):
        # スキームが無くてもパスは保護する
        for raw in ("example.co.jp/campaign/0120-123-456/",
                    "example.co.jp/news/460-0008/"):
            with self.subTest(raw=raw):
                cats = categories(raw)
                self.assertNotIn("PHONE", cats)
                self.assertNotIn("ZIP", cats)

    def test_mynumber_requires_context(self):
        self.assertEqual(values("マイナンバー 123456789012", "MYNUMBER"), ["123456789012"])
        self.assertEqual(values("通し番号 123456789012", "MYNUMBER"), [])

    def test_name_with_honorific(self):
        self.assertIn("山田太郎", values("山田太郎様よろしくお願いします", "NAME"))
        self.assertIn("佐々木", values("佐々木さんと林部長", "NAME"))
        self.assertIn("林", values("佐々木さんと林部長", "NAME"))

    def test_name_not_swallowing_honorific(self):
        # 「佐々木さんと林」のように敬称を巻き込まないこと
        self.assertNotIn("佐々木さんと林", values("佐々木さんと林部長に共有", "NAME"))

    def test_name_without_leading_role_word(self):
        # 「ご担当 山田太郎様」で「担当」を人名に巻き込まない
        for raw, expected in (("ご担当 山田太郎様", "山田太郎"),
                              ("担当者 鈴木花子さん", "鈴木花子"),
                              ("お客様 田中一郎様", "田中一郎"),
                              ("主担当 佐藤健一様", "佐藤健一")):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "NAME"), [expected])

    def test_role_word_alone_is_not_a_name(self):
        for raw in ("ご担当者様へ", "各位 様", "お客様各位"):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "NAME"), [])

    def test_slack_display_name(self):
        # 「山田 太郎 / やまだ / yamada」形式を丸ごと 1 人分として扱う
        for raw in ("山田 太郎 / やまだ / yamada",
                    "山田 太郎 / yamada",
                    "佐々木 健一 / ささき / sasaki-k"):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "NAME"), [raw])

    def test_slack_display_name_with_varied_spacing(self):
        # 姓と名の間の空白は 1 つとは限らない（コピペで 2 つ以上やタブになる）
        for raw in ("山田 太郎 / やまだ / yamada",
                    "山田  太郎 / やまだ / yamada",
                    "山田   太郎 / やまだ / yamada",
                    "山田\u3000太郎 / やまだ / yamada",
                    "山田\t太郎 / やまだ / yamada",
                    "山田太郎 / やまだ / yamada"):
            with self.subTest(raw=repr(raw)):
                self.assertEqual(values(raw, "NAME"), [raw])

    def test_slack_display_name_with_full_name_aliases(self):
        # 読み仮名・ローマ字がフルネームで書かれる形式
        for raw in ("山田 太郎 / やまだ たろう / yamada taro",
                    "山田 太郎 / ヤマダ タロウ / Yamada Taro",
                    "山田 太郎 / やまだ\u3000たろう / yamada-taro",
                    "山田 太郎 / やまだ たろう / yamada taro",
                    "佐々木 健一 / ささき / sasaki-k"):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "NAME"), [raw])

    def test_alias_stops_before_email_or_url(self):
        # 表示名の直後にメールや URL が続いても、本体が消えないこと
        cases = {
            "山田 太郎 / やまだ / yamada / yamada@example.co.jp":
                ("山田 太郎 / やまだ / yamada", "EMAIL"),
            "山田 太郎 / やまだ たろう / yamada taro / https://example.co.jp/":
                ("山田 太郎 / やまだ たろう / yamada taro", "URL"),
        }
        for raw, (expected_name, other) in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "NAME"), [expected_name])
                self.assertTrue(values(raw, other))

    def test_greetings_are_not_aliases(self):
        # 「/」の後ろが挨拶やあいづちなら別名として取り込まない
        for raw, expected in (("鈴木 一郎 / よろしく お願いします", "鈴木 一郎"),
                              ("田中 / ありがとう ございます", "田中"),
                              ("佐藤 / 了解 しました", "佐藤")):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "NAME"), [expected])

    def test_department_is_not_a_given_name(self):
        # 空白を緩めた分、名の位置に来る部署名を弾く
        for raw in ("山田\t営業部", "山田 営業部", "田中  総務課", "鈴木 開発チーム"):
            with self.subTest(raw=repr(raw)):
                found = values(raw, "NAME")
                self.assertEqual(len(found), 1)
                self.assertNotIn("部", found[0])
                self.assertNotIn("課", found[0])
                self.assertNotIn("チーム", found[0])

    def test_slack_alias_does_not_swallow_chat_text(self):
        # 敬称付きの呼びかけの後ろは別名ではないので巻き込まない
        self.assertEqual(values("山田さん / お疲れ様です", "NAME"), ["山田"])
        self.assertEqual(values("田中 / ありがとうございます", "NAME"), ["田中"])

    def test_name_label(self):
        self.assertIn("鈴木花子", values("ご担当者: 鈴木花子", "NAME"))

    def test_org_not_treated_as_person(self):
        found = values("株式会社グロウグループ 御中", "NAME")
        self.assertEqual(found, [])

    def test_org(self):
        self.assertIn("株式会社グロウグループ", values("株式会社グロウグループの件", "ORG"))

    def test_org_abbreviations(self):
        for raw in ("（株）さくら不動産", "(株)さくら不動産", "㈱さくら不動産",
                    "(有)さくら工務店", "㈲さくら工務店"):
            with self.subTest(raw=raw):
                self.assertEqual(values(f"{raw}の件", "ORG"), [raw])

    def test_org_abbreviation_suffix(self):
        self.assertEqual(values("さくら不動産（株）の件", "ORG"), ["さくら不動産（株）"])

    def test_org_with_space_after_corp_type(self):
        self.assertEqual(values("株式会社 さくら不動産の件", "ORG"), ["株式会社 さくら不動産"])

    def test_org_detected_by_onchu(self):
        for raw in ("さくら不動産 御中", "さくら不動産御中", "グロウグループ御中"):
            with self.subTest(raw=raw):
                found = values(raw, "ORG")
                self.assertTrue(found and "御中" not in found[0], found)

    def test_org_industry_suffix(self):
        self.assertEqual(values("さくら工務店に発注", "ORG"), ["さくら工務店"])
        self.assertEqual(values("山田設計事務所に依頼", "ORG"), ["山田設計事務所"])

    def test_org_guess_catches_plain_company(self):
        for raw, expected in (("さくら不動産の件", "さくら不動産"),
                              ("山田建設に依頼", "山田建設"),
                              ("名古屋中央病院様", "名古屋中央病院")):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "ORG"), [expected])

    def test_org_guess_can_be_disabled(self):
        self.assertEqual(values("さくら不動産の件", "ORG", org_guess=False), [])

    def test_common_words_are_not_orgs(self):
        for raw in ("システム開発を担当します", "当社サービスの改善",
                    "病院の予約システムを構築", "弊社の設計事務所",
                    "不動産業界の動向", "グループ会社間の連携"):
            with self.subTest(raw=raw):
                self.assertEqual(values(raw, "ORG"), [])

    def test_org_suffix_not_treated_as_person(self):
        # 「さくら不動産様」の「不動産」を人名として拾わない
        self.assertEqual(values("さくら不動産様", "NAME"), [])

    def test_business_date_survives(self):
        self.assertEqual(values("納品は2026年3月10日です", "BIRTH"), [])

    def test_birth_with_label(self):
        self.assertEqual(values("生年月日: 1985年4月2日", "BIRTH"), ["1985年4月2日"])

    def test_all_dates_option(self):
        self.assertEqual(values("納品は2026年3月10日です", "BIRTH", all_dates=True),
                         ["2026年3月10日"])

    def test_url_masks_domain_only(self):
        found = detect("https://client-a.co.jp/works/detail/ を参照")
        urls = [d for d in found if d.category == "URL"]
        self.assertEqual([d.value for d in urls], ["client-a.co.jp"])
        self.assertEqual(urls[0].display, "ドメイン")

    def test_url_path_is_protected_from_other_rules(self):
        # スラッグ内の数字を電話番号や郵便番号として誤検出しない
        cats = categories("https://client-a.co.jp/campaign/0120-123-456/")
        self.assertNotIn("PHONE", cats)
        self.assertNotIn("ZIP", cats)

    def test_url_query_is_still_scanned(self):
        cats = categories("https://client-a.co.jp/form/?email=a@example.jp&tel=090-1234-5678")
        self.assertIn("EMAIL", cats)
        self.assertIn("PHONE", cats)

    def test_allowlisted_domains_survive(self):
        for url in ("https://developer.mozilla.org/ja/docs/Web",
                    "https://github.com/foo/bar",
                    "https://ja.wordpress.org/support/"):
            with self.subTest(url=url):
                self.assertEqual([d for d in detect(url) if d.category == "URL"], [])

    def test_bare_domain(self):
        self.assertEqual(values("client-a.co.jp のDNSを変更", "URL"), ["client-a.co.jp"])

    def test_filenames_are_not_domains(self):
        self.assertEqual(values("style.css と app.js と index.html", "URL"), [])

    def test_url_full_mode(self):
        found = detect("https://client-a.co.jp/works/detail/", url_mode="full")
        urls = [d for d in found if d.category == "URL"]
        self.assertEqual([d.value for d in urls], ["https://client-a.co.jp/works/detail/"])

    def test_allowlist_applies_in_full_mode(self):
        found = detect("https://github.com/foo/bar", url_mode="full")
        self.assertEqual([d for d in found if d.category == "URL"], [])

    def test_private_ip_is_kept(self):
        for ip in ("192.168.1.5", "127.0.0.1", "10.0.0.1", "172.16.0.9"):
            with self.subTest(ip=ip):
                self.assertEqual(values(f"接続先 {ip}", "IP"), [])

    def test_public_ip_is_masked(self):
        self.assertEqual(values("接続先 203.0.113.5", "IP"), ["203.0.113.5"])


class TestMasking(unittest.TestCase):
    def test_same_value_same_placeholder(self):
        result = mask_text("山田太郎様の件。山田太郎様に再連絡。")
        self.assertEqual(result.text.count("[人名_1]"), 2)

    def test_roundtrip(self):
        vault = Vault()
        original = "山田太郎様(yamada@example.com) 052-123-4567"
        masked = vault.mask(original)
        restored, count = restore_text(masked.text, masked.mapping)
        self.assertEqual(restored, original)
        self.assertEqual(count, 3)

    def test_vault_shared_across_documents(self):
        vault = Vault()
        a = vault.mask("担当は山田太郎様です")
        b = vault.mask("山田太郎様へ再送しました")
        placeholder = a.hits[0]["replacement"]
        self.assertIn(placeholder, b.text)

    def test_redact_leaves_no_mapping(self):
        vault = Vault(MaskConfig(redact=True))
        result = vault.mask("山田太郎様")
        self.assertIn("●", result.text)
        self.assertEqual(vault.mapping, {})

    def test_custom_terms(self):
        config = MaskConfig(custom_terms=[("プロジェクト彗星", "コードネーム")])
        result = mask_text("プロジェクト彗星の進捗", config)
        self.assertNotIn("プロジェクト彗星", result.text)

    def test_category_filter(self):
        config = MaskConfig(categories=["EMAIL"])
        result = mask_text("山田太郎様 yamada@example.com", config)
        self.assertIn("山田太郎", result.text)
        self.assertNotIn("yamada@example.com", result.text)

    def test_load_mapping_continues_numbering(self):
        vault = Vault()
        vault.load_mapping({"[人名_1]": "山田太郎"})
        result = vault.mask("田中一郎様と山田太郎様")
        self.assertIn("[人名_1]", result.text)
        self.assertIn("[人名_2]", result.text)

    def test_domain_roundtrip_keeps_slug(self):
        vault = Vault()
        original = "実績 https://client-a.co.jp/works/nagoya-clinic/ をご覧ください"
        masked = vault.mask(original)
        self.assertIn("/works/nagoya-clinic/", masked.text)
        self.assertNotIn("client-a.co.jp", masked.text)
        restored, _ = restore_text(masked.text, masked.mapping)
        self.assertEqual(restored, original)

    def test_url_full_mode_config(self):
        result = mask_text("https://client-a.co.jp/works/",
                           MaskConfig(url_mode="full"))
        self.assertNotIn("/works/", result.text)

    def test_slack_alias_reused_elsewhere(self):
        vault = Vault()
        text = ("山田 太郎 / やまだ / yamada\n"
                "レビューは yamada にお願いします")
        result = vault.mask(text)
        self.assertNotIn("yamada", result.text)
        # 同一人物と分かるよう枝番で関連付ける
        self.assertIn("[人名_1]", result.text)
        self.assertIn("[人名_1a]", result.text)
        restored, _ = restore_text(result.text, result.mapping)
        self.assertEqual(restored, text)

    def test_romaji_surname_alone_is_linked(self):
        # 「yamada taro」を登録すると、単独の「yamada」も同一人物として拾う
        vault = Vault()
        text = ("山田 太郎 / やまだ たろう / yamada taro\n"
                "レビューは yamada さんにお願いします")
        result = vault.mask(text)
        self.assertNotIn("yamada さん", result.text)
        self.assertIn("[人名_1]", result.text)
        self.assertIn("[人名_1a]", result.text)
        restored, _ = restore_text(result.text, result.mapping)
        self.assertEqual(restored, text)

    def test_alias_placeholder_survives_load_mapping(self):
        vault = Vault()
        vault.load_mapping({"[人名_1]": "山田 太郎 / やまだ / yamada",
                            "[人名_1a]": "yamada"})
        result = vault.mask("担当は山田太郎様です")
        # 枝番は採番に影響しないので次は [人名_2]
        self.assertIn("[人名_2]", result.text)

    def test_empty_input(self):
        self.assertEqual(mask_text("").text, "")


if __name__ == "__main__":
    unittest.main()
