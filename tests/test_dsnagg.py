"""多封退信回执归并（DSN aggregate）单元测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailtrace.parsing import aggregate_dsn, split_batch_headers  # noqa: E402
from mailtrace.parsing.sample import SAMPLE_DSN_AGGREGATE  # noqa: E402

try:  # Flask 相关测试在未安装 Flask 时跳过（解析核心仅需标准库）
    from app import create_app
except ImportError:  # pragma: no cover
    create_app = None


def dsn_mail(body: str, boundary: str = "B") -> str:
    """构造一封含单个 message/delivery-status 部分的完整 multipart/report。"""
    return (
        "From: Mailer-Daemon <md@mx.example>\r\n"
        "Content-Type: multipart/report; report-type=delivery-status;\r\n"
        f' boundary="{boundary}"\r\n\r\n'
        f"--{boundary}\r\n"
        "Content-Type: text/plain\r\n\r\n"
        "human readable bounce notice\r\n"
        f"--{boundary}\r\n"
        "Content-Type: message/delivery-status\r\n\r\n"
        f"{body}\r\n"
        f"--{boundary}--\r\n"
    )


def recipient_block(recipient, action, status, diag=None, extra=""):
    lines = [
        f"Final-Recipient: rfc822; {recipient}",
        f"Action: {action}",
        f"Status: {status}",
    ]
    if diag is not None:
        lines.append(f"Diagnostic-Code: smtp;{diag}")
    if extra:
        lines.append(extra)
    # DSN 字段块之间必须以空行分隔（RFC 3464）
    return "\n".join(lines) + "\n\n"


def envelope(envelope_id="QID-001"):
    lines = ["Reporting-MTA: dns;mx.example"]
    if envelope_id is not None:
        lines.append(f"Original-Envelope-Id: {envelope_id}")
    return "\n".join(lines) + "\n\n"


PLAIN_NOTICE = "From: Postmaster <pm@mx.example>\nSubject: delivery problem\n\n550 mailbox full\n"


class GroupingTests(unittest.TestCase):
    def test_same_key_merges_across_mails_in_input_order(self):
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("alice@example.com", "delayed", "4.7.1")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("alice@example.com", "delivered", "2.0.0")
        )
        result = aggregate_dsn([mail1, mail2])
        self.assertNotIn("error", result)
        self.assertEqual(result["message_count"], 2)
        self.assertEqual(result["inspected_count"], 2)
        self.assertEqual(result["group_count"], 1)
        self.assertEqual(result["unmerged_count"], 0)
        group = result["groups"][0]
        self.assertEqual(
            group["key"],
            {
                "original_envelope_id": "QID-1",
                "final_recipient_raw": "rfc822; alice@example.com",
            },
        )
        self.assertEqual(group["source_indexes"], [1, 2])
        self.assertEqual(group["event_count"], 2)
        # 轨迹按输入顺序：暂缓 -> 成功结案
        self.assertEqual(
            [e["result"] for e in group["events"]],
            ["deferred", "success"],
        )
        self.assertEqual([e["email_index"] for e in group["events"]], [1, 2])
        self.assertEqual(group["final_result"], "success")
        self.assertTrue(group["closed"])
        self.assertFalse(group["conflict"])
        # 逐次证据保留原始字段
        self.assertIn(
            "Status: 4.7.1", group["events"][0]["raw_fields"]["status"]
        )
        self.assertIn("Final-Recipient", group["events"][0]["raw_block"])

    def test_same_address_different_envelope_id_not_merged(self):
        # 不凭收件地址单独合并：地址相同但信封标识不同属于不同投递
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("alice@example.com", "failed", "5.1.1")
        )
        mail2 = dsn_mail(
            envelope("QID-2")
            + recipient_block("alice@example.com", "delivered", "2.0.0")
        )
        result = aggregate_dsn([mail1, mail2])
        self.assertEqual(result["group_count"], 2)
        self.assertEqual(result["conflict_count"], 0)
        finals = {g["key"]["original_envelope_id"]: g["final_result"]
                  for g in result["groups"]}
        self.assertEqual(finals, {"QID-1": "permanent", "QID-2": "success"})

    def test_final_recipient_raw_case_difference_not_merged(self):
        # Final-Recipient 取原值：大小写不同即不同投递键
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("Alice@example.com", "failed", "5.1.1")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("alice@example.com", "failed", "5.1.1")
        )
        result = aggregate_dsn([mail1, mail2])
        self.assertEqual(result["group_count"], 2)

    def test_recipients_keyed_per_dsn_part(self):
        # 同一封邮件两个投递状态部分，各自的 Original-Envelope-Id 不同
        source = (
            "Content-Type: multipart/mixed; boundary=B\n\n"
            "--B\n"
            "Content-Type: message/delivery-status\n\n"
            "Reporting-MTA: dns;mx.example\n"
            "Original-Envelope-Id: QID-1\n\n"
            "Final-Recipient: rfc822; a@example.com\n"
            "Action: failed\nStatus: 5.1.1\n\n"
            "--B\n"
            "Content-Type: message/delivery-status\n\n"
            "Reporting-MTA: dns;mx.example\n"
            "Original-Envelope-Id: QID-2\n\n"
            "Final-Recipient: rfc822; a@example.com\n"
            "Action: failed\nStatus: 5.1.1\n\n"
            "--B--\n"
        )
        result = aggregate_dsn([source])
        self.assertEqual(result["group_count"], 2)
        ids = sorted(g["key"]["original_envelope_id"] for g in result["groups"])
        self.assertEqual(ids, ["QID-1", "QID-2"])


class UnmergedTests(unittest.TestCase):
    def test_missing_envelope_id_unmerged(self):
        mail = dsn_mail(
            envelope(None)
            + recipient_block("dave@example.com", "failed", "5.1.1")
        )
        result = aggregate_dsn([mail])
        self.assertEqual(result["group_count"], 0)
        self.assertEqual(result["unmerged_count"], 1)
        entry = result["unmerged"][0]
        self.assertEqual(entry["email_index"], 1)
        self.assertEqual(entry["final_recipient"], "dave@example.com")
        self.assertTrue(
            any("Original-Envelope-Id" in why for why in entry["reasons"])
        )

    def test_empty_envelope_id_unmerged(self):
        mail = dsn_mail(
            "Reporting-MTA: dns;mx.example\n"
            "Original-Envelope-Id:\n\n"
            + recipient_block("dave@example.com", "failed", "5.1.1")
        )
        result = aggregate_dsn([mail])
        self.assertEqual(result["group_count"], 0)
        self.assertEqual(result["unmerged_count"], 1)
        self.assertTrue(
            any("为空" in why for why in result["unmerged"][0]["reasons"])
        )

    def test_duplicate_envelope_id_unmerged(self):
        mail = dsn_mail(
            "Reporting-MTA: dns;mx.example\n"
            "Original-Envelope-Id: QID-1\n"
            "Original-Envelope-Id: QID-2\n\n"
            + recipient_block("dave@example.com", "failed", "5.1.1")
        )
        result = aggregate_dsn([mail])
        self.assertEqual(result["group_count"], 0)
        self.assertEqual(result["unmerged_count"], 1)
        entry = result["unmerged"][0]
        self.assertTrue(
            any("不唯一" in why for why in entry["reasons"])
        )
        self.assertTrue(
            any("QID-1" in why and "QID-2" in why for why in entry["reasons"])
        )

    def test_review_block_unmerged_with_review_reasons(self):
        mail = dsn_mail(
            envelope("QID-1")
            + recipient_block("weird@example.com", "failed", "4.4.1")
        )
        result = aggregate_dsn([mail])
        self.assertEqual(result["group_count"], 0)
        self.assertEqual(result["unmerged_count"], 1)
        entry = result["unmerged"][0]
        self.assertEqual(entry["result"], "review")
        self.assertTrue(any("待核对" in why for why in entry["reasons"]))
        # 判读阶段的具体原因一并保留
        self.assertTrue(any("矛盾" in why for why in entry["reasons"]))

    def test_unmerged_does_not_block_other_recipients(self):
        mail1 = dsn_mail(
            envelope(None)
            + recipient_block("dave@example.com", "failed", "5.1.1")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("alice@example.com", "delivered", "2.0.0")
        )
        result = aggregate_dsn([mail1, mail2])
        self.assertEqual(result["group_count"], 1)
        self.assertEqual(result["unmerged_count"], 1)
        self.assertEqual(result["merged_recipient_count"], 1)


class TrajectoryTests(unittest.TestCase):
    def test_deferred_then_permanent_closes(self):
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "delayed", "4.7.1")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "delayed", "4.2.2")
        )
        mail3 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "failed", "5.1.1")
        )
        result = aggregate_dsn([mail1, mail2, mail3])
        group = result["groups"][0]
        self.assertEqual(
            [e["result"] for e in group["events"]],
            ["deferred", "deferred", "permanent"],
        )
        self.assertEqual(group["final_result"], "permanent")
        self.assertTrue(group["closed"])
        self.assertFalse(group["conflict"])

    def test_deferred_only_stays_open(self):
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "delayed", "4.7.1")
        )
        result = aggregate_dsn([mail1])
        group = result["groups"][0]
        self.assertEqual(group["final_result"], "deferred")
        self.assertFalse(group["closed"])
        self.assertFalse(group["conflict"])

    def test_conflict_after_closure_not_overwritten(self):
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("bob@example.com", "failed", "5.1.1")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("bob@example.com", "delivered", "2.0.0")
        )
        result = aggregate_dsn([mail1, mail2])
        self.assertEqual(result["conflict_count"], 1)
        group = result["groups"][0]
        # 不静默覆盖：最终状态保持结案时的永久失败
        self.assertEqual(group["final_result"], "permanent")
        self.assertTrue(group["closed"])
        self.assertTrue(group["conflict"])
        self.assertEqual(len(group["conflicts"]), 1)
        conflict = group["conflicts"][0]
        self.assertEqual(conflict["email_index"], 2)
        self.assertEqual(conflict["result"], "success")
        self.assertIn("不覆盖", conflict["reason"])
        # 冲突事件仍保留在轨迹中
        self.assertEqual(
            [e["result"] for e in group["events"]],
            ["permanent", "success"],
        )

    def test_deferred_after_closure_is_conflict(self):
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "delivered", "2.0.0")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "delayed", "4.7.1")
        )
        result = aggregate_dsn([mail1, mail2])
        group = result["groups"][0]
        self.assertEqual(group["final_result"], "success")
        self.assertTrue(group["conflict"])

    def test_same_category_after_closure_is_not_conflict(self):
        mail1 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "failed", "5.1.1")
        )
        mail2 = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "failed", "5.1.1")
        )
        result = aggregate_dsn([mail1, mail2])
        group = result["groups"][0]
        self.assertEqual(group["final_result"], "permanent")
        self.assertFalse(group["conflict"])
        self.assertEqual(group["event_count"], 2)


class MessageErrorTests(unittest.TestCase):
    def test_mail_without_dsn_part_reported_others_still_merged(self):
        good = dsn_mail(
            envelope("QID-1")
            + recipient_block("alice@example.com", "delivered", "2.0.0")
        )
        result = aggregate_dsn([good, PLAIN_NOTICE])
        self.assertNotIn("error", result)
        self.assertEqual(result["message_count"], 2)
        self.assertEqual(result["inspected_count"], 1)
        self.assertEqual(len(result["message_errors"]), 1)
        self.assertEqual(result["message_errors"][0]["index"], 2)
        self.assertIn(
            "message/delivery-status", result["message_errors"][0]["error"]
        )
        # 其余邮件照常归并
        self.assertEqual(result["group_count"], 1)
        self.assertEqual(result["groups"][0]["source_indexes"], [1])

    def test_all_mails_without_dsn_part_returns_error(self):
        result = aggregate_dsn([PLAIN_NOTICE, PLAIN_NOTICE])
        self.assertIn("error", result)
        self.assertEqual(result["inspected_count"], 0)
        self.assertEqual(len(result["message_errors"]), 2)
        self.assertEqual(result["groups"], [])

    def test_empty_sources_returns_error(self):
        result = aggregate_dsn([])
        self.assertIn("error", result)
        self.assertEqual(result["message_count"], 0)


class SampleTests(unittest.TestCase):
    def test_sample_aggregate(self):
        sources = split_batch_headers(SAMPLE_DSN_AGGREGATE)
        self.assertEqual(len(sources), 6)
        result = aggregate_dsn(sources)
        self.assertNotIn("error", result)
        self.assertEqual(result["inspected_count"], 5)
        self.assertEqual(len(result["message_errors"]), 1)
        self.assertEqual(result["message_errors"][0]["index"], 6)
        # alice（暂缓->成功结案）、bob（永久失败->冲突）、carol（独立组）
        self.assertEqual(result["group_count"], 3)
        self.assertEqual(result["conflict_count"], 1)
        self.assertEqual(result["unmerged_count"], 2)
        by_recipient = {g["final_recipient"]: g for g in result["groups"]}
        alice = by_recipient["alice@final.example"]
        self.assertEqual(alice["final_result"], "success")
        self.assertEqual(alice["source_indexes"], [1, 2])
        self.assertFalse(alice["conflict"])
        bob = by_recipient["bob@final.example"]
        self.assertEqual(bob["final_result"], "permanent")
        self.assertTrue(bob["conflict"])
        self.assertEqual(bob["source_indexes"], [1, 3])
        carol = by_recipient["carol@final.example"]
        self.assertEqual(carol["final_result"], "permanent")
        self.assertEqual(carol["source_indexes"], [4])
        # 未归并：缺 Original-Envelope-Id 的 dave + 待核对的 weird
        unmerged_recipients = [u["final_recipient"] for u in result["unmerged"]]
        self.assertEqual(
            unmerged_recipients,
            ["dave@final.example", "weird@final.example"],
        )


@unittest.skipIf(create_app is None, "未安装 Flask")
class DsnAggregateApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_api_success_structure(self):
        sources = split_batch_headers(SAMPLE_DSN_AGGREGATE)
        resp = self.client.post("/api/dsn/aggregate", json={"sources": sources})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data, aggregate_dsn(sources))
        self.assertEqual(data["group_count"], 3)
        self.assertEqual(data["conflict_count"], 1)

    def test_api_single_source_ok(self):
        mail = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "failed", "5.1.1")
        )
        resp = self.client.post("/api/dsn/aggregate", json={"sources": [mail]})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["group_count"], 1)

    def test_api_partial_bad_mail_still_200(self):
        good = dsn_mail(
            envelope("QID-1")
            + recipient_block("a@example.com", "failed", "5.1.1")
        )
        resp = self.client.post(
            "/api/dsn/aggregate", json={"sources": [good, PLAIN_NOTICE]}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["message_errors"]), 1)
        self.assertEqual(data["group_count"], 1)

    def test_api_all_bad_returns_400(self):
        resp = self.client.post(
            "/api/dsn/aggregate", json={"sources": [PLAIN_NOTICE]}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_non_json_returns_400(self):
        resp = self.client.post(
            "/api/dsn/aggregate", data={"sources": "x"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_non_list_sources_returns_400(self):
        resp = self.client.post(
            "/api/dsn/aggregate", json={"sources": "not-a-list"}
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_empty_list_returns_400(self):
        resp = self.client.post("/api/dsn/aggregate", json={"sources": []})
        self.assertEqual(resp.status_code, 400)

    def test_api_blank_item_returns_400(self):
        resp = self.client.post(
            "/api/dsn/aggregate", json={"sources": ["  "]}
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_non_string_item_returns_400(self):
        resp = self.client.post(
            "/api/dsn/aggregate", json={"sources": [123]}
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_size_limit_returns_400(self):
        app = create_app()
        app.config["MAX_INPUT_BYTES"] = 64
        client = app.test_client()
        resp = client.post(
            "/api/dsn/aggregate", json={"sources": ["x" * 1024]}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("上限", resp.get_json()["error"])

    def test_form_page_renders_groups(self):
        resp = self.client.post(
            "/dsn-aggregate", data={"source_dsn_aggregate": SAMPLE_DSN_AGGREGATE}
        )
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("多封退信回执归并结果", html)
        self.assertIn("QID-001", html)
        self.assertIn("alice@final.example", html)
        self.assertIn("结案后冲突", html)
        self.assertIn("未归并清单", html)
        self.assertIn("dave@final.example", html)
        self.assertIn("未参与归并的邮件", html)

    def test_form_empty_input_shows_error(self):
        resp = self.client.post(
            "/dsn-aggregate", data={"source_dsn_aggregate": "   "}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("未识别到任何退信邮件", resp.get_data(as_text=True))

    def test_index_page_has_aggregate_section(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("多封退信回执归并", html)
        self.assertIn("/api/dsn/aggregate", html)


if __name__ == "__main__":
    unittest.main()
