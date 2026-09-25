"""单封邮件脱敏分享报告：仅保留路径骨架，替换所有可识别值。

设计要点：
- 直接复用 :func:`mailtrace.parsing.parser.analyze_headers` 的解析结果
  （投递顺序、时间、相邻耗时、异常），不重复实现 Received 解析。
- 按**投递顺序**（发件方 -> 收件方）为首次出现的不同主机名分配本次
  请求内稳定的别名（``H1``、``H2``……）；IP 别名（``IP1``、
  ``IP2``……）**只分配给解析器按 ``from`` 子句界定后提取的对端 IP**
  （即每跳 ``ip`` 字段），``by`` 等其他位置出现的地址字面量不会获得
  IP 别名。同一值（忽略主机名大小写与末尾点、剥去 ``[ ]`` 与
  Postfix 的 ``IPv6:`` 前缀）在节点、来源（from）与上一跳标签中
  始终得到同一个别名；缺失身份的节点对应字段留空（``None``）。
- 输出采用白名单：仅包含路径序号、各类别名、UTC 时间、相邻耗时及
  异常级别 / 说明。原始头部、邮件摘要、Received ID、协议等可识别
  文本一律不输出。
"""

from __future__ import annotations

from ipaddress import ip_address

from mailtrace.parsing.parser import analyze_headers

# 解析器对“完全无身份节点”使用的展示标签，脱敏后留空
UNKNOWN_NODE = "(未知节点)"
_HOST_PREFIX = "H"
_IP_PREFIX = "IP"


def _canon_host(value: str | None) -> str | None:
    """把主机名标签规范化为查表键；IP 字面量或无身份时返回 ``None``。

    主机名忽略大小写与末尾点（与 compare/batch 的规范化一致）；
    方括号字面量与 ``IPv6:`` / ``IPv4:`` 前缀剥去后能按 IP 校验的值
    不由主机名表处理（交由 :func:`_host_alias` 查 IP 别名表）。
    """
    if not value:
        return None
    token = value.strip()
    if len(token) >= 2 and token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    if token.lower().startswith(("ipv6:", "ipv4:")):
        token = token[5:]
    token = token.rstrip(".").strip()
    if not token or token == UNKNOWN_NODE:
        return None
    try:
        ip_address(token)
    except ValueError:
        return token.lower()
    return None


def _canon_ip(value: str | None) -> str | None:
    """把对端 IP 规范化为查表键；非合法 IP / 空值时返回 ``None``。"""
    if not value:
        return None
    token = value.strip()
    if len(token) >= 2 and token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    if token.lower().startswith(("ipv6:", "ipv4:")):
        token = token[5:]
    try:
        return str(ip_address(token))
    except ValueError:
        return None


def build_share_report(raw_headers: str) -> dict:
    """由单封邮件原始头部生成脱敏分享报告。

    没有 ``Received`` 字段时返回 ``{"error": ...}``（调用方据此回 400）。
    """
    result = analyze_headers(raw_headers)
    if result["hop_count"] == 0:
        return {"error": "头部中未找到 Received 字段，无法生成脱敏分享报告"}

    host_aliases: dict[str, str] = {}
    ip_aliases: dict[str, str] = {}

    # 仅解析器确认的对端 IP 可以取得 IP 别名；先按投递顺序登记，
    # 保证 IP1、IP2…… 的编号即对端在路径中的出现顺序。
    for hop in result["path"]:
        key = _canon_ip(hop.get("ip"))
        if key is not None and key not in ip_aliases:
            ip_aliases[key] = f"{_IP_PREFIX}{len(ip_aliases) + 1}"

    def host_alias(value: str | None) -> str | None:
        """节点 / 来源 / 上一跳标签的别名：

        若标签本身是已登记对端 IP 的字面量（如 ``[10.0.0.5]`` 与该跳
        对端 IP 同源），沿用其 IP 别名；其余标签（包括作为接收主机
        身份出现的地址字面量）按主机名分配 H 别名——IP 别名表只对
        解析器确认的对端 IP 开放。
        """
        ip_key = _canon_ip(value)
        if ip_key is not None:
            peer_alias = ip_aliases.get(ip_key)
            if peer_alias is not None:
                return peer_alias
        key = _canon_host(value)
        if key is None:
            if ip_key is not None:
                # 非对端 IP 的地址字面量（如 by 10.1.2.3）：
                # 不分配 IP 别名，但仍以 H 别名掩码并保留节点身份
                key = f"ip:{ip_key}"
            else:
                return None
        alias = host_aliases.get(key)
        if alias is None:
            alias = f"{_HOST_PREFIX}{len(host_aliases) + 1}"
            host_aliases[key] = alias
        return alias

    def peer_ip_alias(value: str | None) -> str | None:
        key = _canon_ip(value)
        return ip_aliases.get(key) if key is not None else None

    rows: list[dict] = []
    for hop in result["path"]:
        # 注册顺序即投递顺序；同一跳内先节点、再来源、再对端 IP
        node_alias = host_alias(hop.get("node"))
        from_alias = host_alias(hop.get("from_host"))
        ip_alias = peer_ip_alias(hop.get("ip"))
        # 上一跳标签与上一节点的节点别名天然一致（值相同、表共享）
        delay_from_alias = host_alias(hop.get("delay_from"))

        rows.append(
            {
                "path_index": hop["path_index"],
                "node": node_alias,
                "from_host": from_alias,
                "ip": ip_alias,
                "time_utc": hop.get("time_utc"),
                "delay_from": delay_from_alias,
                "delay_seconds": hop.get("delay_seconds"),
                "delay_human": hop.get("delay_human"),
                "anomalies": [
                    {"level": a["level"], "message": a["message"]}
                    for a in hop.get("anomalies", [])
                ],
            }
        )

    return {
        "host_aliases": list(host_aliases.values()),
        "ip_aliases": list(ip_aliases.values()),
        "path": rows,
    }
