"""多封退信回执（DSN）归并：按投递键把同一投递的多次回执合并为状态轨迹。

归并口径：
- 输入为多封**完整原始退信邮件**（每封应含 ``message/delivery-status``
  投递状态部分），逐封复用 :func:`mailtrace.parsing.dsn.inspect_dsn`
  的逐收件人判读结果，不重新实现 MIME 与增强状态码解析。
- 每个收件人报告块的**投递键** = 所属投递状态部分中唯一且非空的
  ``Original-Envelope-Id``（每消息字段块，折行展开后的原值）+
  该块的 ``Final-Recipient`` 原值（折行展开后的完整字段值，含地址
  类型前缀，大小写保持原文）。**绝不只凭收件人地址合并**：地址相同
  但信封标识不同的报告属于不同投递，各自成组。
- 以下情形的收件人块列入**未归并清单**并逐条说明原因：
  待核对块（Status 缺失 / 与 Action 矛盾等判读阶段即存疑的块）、
  所属投递状态部分缺少 ``Original-Envelope-Id``、该标识出现多次
  （不唯一）、标识为空，或 ``Final-Recipient`` 原值为空。
- 每组按**输入顺序**（邮件序号 → 该封内收件人序号）排列状态轨迹：
  暂缓（deferred）之后的成功 / 永久失败使轨迹**结案**；结案后再出现
  **不同类别**（如永久失败后又报告成功）标为**冲突**并保留原结案
  状态，不静默覆盖；同类别的重复报告视为重复确认，不算冲突。
- 某封邮件没有投递状态部分时记入 ``message_errors``（含邮件序号），
  其余邮件照常参与归并；所有邮件都没有投递状态部分时返回
  ``{"error": ...}``（调用方据此返回 400）。
"""

from __future__ import annotations

from mailtrace.parsing.dsn import (
    RESULT_DEFERRED,
    RESULT_PERMANENT,
    RESULT_SUCCESS,
    _STATUS_LABELS,
    inspect_dsn,
)

# Original-Envelope-Id 是 RFC 3464 的每消息字段（字段名比较忽略大小写）
_ENVELOPE_ID_FIELD = "original-envelope-id"

# 结案（终态）类别：成功 / 永久失败；暂缓仍可能由后续回执结案
_CLOSED_RESULTS = {RESULT_SUCCESS, RESULT_PERMANENT}


def _part_envelope_ids(inspected: dict, dsn_part: int) -> list[str]:
    """收集某投递状态部分全部每消息字段块中的 Original-Envelope-Id 原值。

    同一部分出现多个每消息字段块、或单块内字段重复时，所有出现都计入，
    由调用方按“必须唯一且非空”判定。
    """
    values: list[str] = []
    for env in inspected["envelope_blocks"]:
        if env["dsn_part"] != dsn_part:
            continue
        for field in env["fields"]:
            if field["name"].lower() == _ENVELOPE_ID_FIELD:
                values.append(field["value"])
    return values


def _delivery_key(
    inspected: dict, recipient: dict
) -> tuple[tuple[str, str] | None, list[str]]:
    """计算收件人报告块的投递键。

    返回 ``(投递键, 无法组成键的原因列表)``；原因列表非空时投递键为
    ``None``，该块应列入未归并清单。
    """
    reasons: list[str] = []
    ids = _part_envelope_ids(inspected, recipient["dsn_part"])
    envelope_id: str | None = None
    if not ids:
        reasons.append(
            "所属投递状态部分的每消息字段块中没有 Original-Envelope-Id，"
            "无法组成投递键（不凭收件地址单独合并）"
        )
    elif len(ids) > 1:
        shown = "、".join(f"“{value or '（空）'}”" for value in ids)
        reasons.append(
            f"所属投递状态部分中 Original-Envelope-Id 出现 {len(ids)} 次"
            f"（{shown}），标识不唯一，无法组成投递键"
        )
    elif not ids[0]:
        reasons.append("Original-Envelope-Id 字段为空，无法组成投递键")
    else:
        envelope_id = ids[0]

    final_raw = recipient.get("final_recipient_raw")
    if not final_raw:
        reasons.append("Final-Recipient 原值为空，无法组成投递键")

    if reasons:
        return None, reasons
    return (envelope_id, final_raw), []


def _event(email_index: int, recipient: dict) -> dict:
    """从判读结果中提取一次状态轨迹事件（含逐次证据）。"""
    return {
        "email_index": email_index,
        "recipient_index": recipient["index"],
        "dsn_part": recipient["dsn_part"],
        "result": recipient["result"],
        "result_label": recipient["result_label"],
        "action": recipient["action"],
        "status": recipient["status"],
        "status_class": recipient["status_class"],
        "diagnostic_code": recipient["diagnostic_code"],
        "diagnostic_raw": recipient["diagnostic_raw"],
        "raw_fields": recipient["raw_fields"],
        "raw_block": recipient["raw_block"],
    }


def _unmerged_entry(email_index: int, recipient: dict, reasons: list[str]) -> dict:
    return {
        "email_index": email_index,
        "recipient_index": recipient["index"],
        "dsn_part": recipient["dsn_part"],
        "final_recipient": recipient["final_recipient"],
        "final_recipient_raw": recipient["final_recipient_raw"],
        "result": recipient["result"],
        "result_label": recipient["result_label"],
        "reasons": reasons,
        "raw_block": recipient["raw_block"],
    }


def _close_group(group: dict) -> None:
    """按输入顺序走完一组的状态轨迹，得出最终状态与冲突清单。

    状态机：未结案时暂缓可反复出现；首个成功 / 永久失败结案；结案后
    同类别为重复确认（忽略），不同类别记入 ``conflicts`` 且不覆盖
    已结案状态。
    """
    final: str | None = None
    closed = False
    conflicts: list[dict] = []
    for event in group["events"]:
        result = event["result"]
        if final is None:
            final = result
            closed = result in _CLOSED_RESULTS
            continue
        if not closed:
            if result in _CLOSED_RESULTS:
                final = result
                closed = True
            # 暂缓之后又暂缓：轨迹仍未结案
            continue
        if result != final:
            conflicts.append(
                {
                    "email_index": event["email_index"],
                    "recipient_index": event["recipient_index"],
                    "result": result,
                    "result_label": event["result_label"],
                    "reason": (
                        f"轨迹已结案为「{_STATUS_LABELS[final]}」，第 "
                        f"{event['email_index']} 封又报告不同类别"
                        f"「{event['result_label']}」：标为冲突，"
                        "保留原结案状态，不覆盖"
                    ),
                }
            )
    group["final_result"] = final
    group["final_label"] = _STATUS_LABELS[final]
    group["closed"] = closed
    group["conflict"] = bool(conflicts)
    group["conflicts"] = conflicts


def aggregate_dsn(sources: list[str]) -> dict:
    """把多封完整原始退信邮件按投递键归并为逐组状态轨迹。

    参数为完整原始退信邮件字符串列表（页面粘贴文本可先用
    :func:`mailtrace.parsing.batch.split_batch_headers` 切分）。
    返回页面与 ``POST /api/dsn/aggregate`` 共用的结构化结果。
    """
    message_errors: list[dict] = []
    unmerged: list[dict] = []
    groups: dict[tuple[str, str], dict] = {}
    inspected_count = 0
    recipient_total = 0

    if not sources:
        return {
            "error": "请至少提供一封完整原始退信邮件"
                     "（含 message/delivery-status 投递状态部分）",
            "message_count": 0,
            "inspected_count": 0,
            "message_errors": message_errors,
            "recipient_total": 0,
            "merged_recipient_count": 0,
            "group_count": 0,
            "unmerged_count": 0,
            "conflict_count": 0,
            "groups": [],
            "unmerged": unmerged,
        }

    for email_index, source in enumerate(sources, start=1):
        inspected = inspect_dsn(source)
        if inspected.get("error"):
            # 该封没有投递状态部分：单独报错，其余邮件仍参与归并
            message_errors.append(
                {"index": email_index, "error": inspected["error"]}
            )
            continue
        inspected_count += 1
        recipient_total += inspected["recipient_count"]

        for recipient in inspected["recipients"]:
            if recipient["review"]:
                reasons = [
                    "该收件人报告块判读为待核对（字段缺失或自相矛盾），"
                    "不参与归并"
                ]
                reasons.extend(recipient["review_reasons"])
                unmerged.append(_unmerged_entry(email_index, recipient, reasons))
                continue

            key, key_reasons = _delivery_key(inspected, recipient)
            if key is None:
                unmerged.append(
                    _unmerged_entry(email_index, recipient, key_reasons)
                )
                continue

            group = groups.get(key)
            if group is None:
                group = {
                    "key": {
                        "original_envelope_id": key[0],
                        "final_recipient_raw": key[1],
                    },
                    "final_recipient": recipient["final_recipient"],
                    "recipient_type": recipient["recipient_type"],
                    "source_indexes": [],
                    "events": [],
                }
                groups[key] = group
            if email_index not in group["source_indexes"]:
                group["source_indexes"].append(email_index)
            group["events"].append(_event(email_index, recipient))

    if inspected_count == 0:
        return {
            "error": "所有邮件中均未找到 message/delivery-status 投递状态"
                     "部分，无法进行归并",
            "message_count": len(sources),
            "inspected_count": 0,
            "message_errors": message_errors,
            "recipient_total": 0,
            "merged_recipient_count": 0,
            "group_count": 0,
            "unmerged_count": 0,
            "conflict_count": 0,
            "groups": [],
            "unmerged": unmerged,
        }

    group_list = list(groups.values())
    for index, group in enumerate(group_list, start=1):
        group["index"] = index
        group["event_count"] = len(group["events"])
        _close_group(group)

    return {
        "message_count": len(sources),
        "inspected_count": inspected_count,
        "message_errors": message_errors,
        "recipient_total": recipient_total,
        "merged_recipient_count": sum(
            len(group["events"]) for group in group_list
        ),
        "group_count": len(group_list),
        "unmerged_count": len(unmerged),
        "conflict_count": sum(1 for group in group_list if group["conflict"]),
        "groups": group_list,
        "unmerged": unmerged,
        "notice": "归并以投递键（所属投递状态部分中唯一且非空的 "
                  "Original-Envelope-Id + Final-Recipient 原值）为单位，"
                  "不凭收件地址单独合并；待核对块与标识缺失 / 重复的块列入"
                  "未归并清单并说明原因。每组按输入顺序排列状态轨迹，"
                  "暂缓可由成功 / 永久失败结案；结案后再出现不同类别标为"
                  "冲突，保留原结案状态，不静默覆盖。",
    }
