#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""逐条检测上游 TVBox 接口，只把可用源同步到本地。"""

import argparse
import base64
import gzip
import json
import re
import sys
import time
from pathlib import Path

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
TIMEOUT = 15
RETRIES = 2
KNOWN_KEYS = ("sites", "lives", "parses", "rules", "spider", "urls", "ads", "wallpaper")


def decode_payload(raw, depth=0):
    """兼容普通 JSON、JSON 字符串、Base64 和 gzip 包装。"""
    if depth > 4:
        raise ValueError("响应嵌套过深")
    data = raw.lstrip(b"\xef\xbb\xbf \t\r\n")
    if data.startswith(b"\x1f\x8b"):
        return decode_payload(gzip.decompress(data), depth + 1)

    text = data.decode("utf-8-sig", errors="replace").strip()
    candidates = [text]
    # 部分接口在 JSON 前后附带少量说明文字，提取最外层 JSON。
    first_obj = text.find("{")
    first_arr = text.find("[")
    starts = [x for x in (first_obj, first_arr) if x >= 0]
    if starts:
        start = min(starts)
        end = max(text.rfind("}"), text.rfind("]"))
        if end > start:
            candidates.append(text[start:end + 1])

    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, str):
                return decode_payload(obj.encode("utf-8"), depth + 1)
            return obj
        except Exception:
            pass

    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            padded = compact.replace("-", "+").replace("_", "/")
            padded += "=" * ((4 - len(padded) % 4) % 4)
            decoded = base64.b64decode(padded, validate=False)
            return decode_payload(decoded, depth + 1)
        except Exception:
            pass
    raise ValueError("响应不是可识别的 JSON TVBox 配置")


def has_tvbox_content(obj, depth=0):
    if depth > 5:
        return False
    if isinstance(obj, dict):
        for key in KNOWN_KEYS:
            value = obj.get(key)
            if key == "spider" and isinstance(value, str) and value.strip():
                return True
            if isinstance(value, (list, dict)) and len(value) > 0:
                return True
        # 兼容 data/result/config 等外层包装。
        for key in ("data", "result", "config", "json", "payload"):
            if key in obj and has_tvbox_content(obj[key], depth + 1):
                return True
    elif isinstance(obj, list):
        return any(has_tvbox_content(item, depth + 1) for item in obj[:20] if isinstance(item, (dict, list)))
    return False


def probe(url):
    last_error = "未知错误"
    for attempt in range(RETRIES + 1):
        try:
            response = requests.get(
                url,
                headers={"User-Agent": UA, "Accept": "application/json,text/plain,*/*"},
                timeout=TIMEOUT,
                allow_redirects=True,
            )
            if response.status_code != 200:
                raise ValueError(f"HTTP {response.status_code}")
            if len(response.content) < 20:
                raise ValueError(f"响应过短（{len(response.content)} 字节）")
            obj = decode_payload(response.content)
            if not has_tvbox_content(obj):
                raise ValueError("JSON 有效，但未发现非空 TVBox 配置字段")
            return True, f"通过，HTTP 200，{len(response.content)} 字节"
        except Exception as exc:
            last_error = str(exc)
            if attempt < RETRIES:
                time.sleep(1.5 * (attempt + 1))
    return False, last_error


def read_sources(path):
    result = {}
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "," not in stripped:
            continue
        parts = [part.strip() for part in stripped.split(",")]
        name, urls = parts[0], [x for x in parts[1:] if x]
        if name and urls:
            result[name] = ",".join([name] + urls)
    return result


def main():
    parser = argparse.ArgumentParser(description="逐条检测上游 TVBox 源")
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--local", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    local_sources = read_sources(args.local)
    upstream_lines = Path(args.upstream).read_text(encoding="utf-8-sig").splitlines()
    output_lines = []
    report = []
    passed_sources = skipped_sources = passed_urls = failed_urls = 0

    for line in upstream_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "," not in stripped:
            output_lines.append(line)
            continue

        parts = [part.strip() for part in stripped.split(",")]
        name, urls = parts[0], [x for x in parts[1:] if x]
        if not name or not urls:
            output_lines.append(line)
            continue

        good_urls = []
        for url in urls:
            ok, detail = probe(url)
            if ok:
                good_urls.append(url)
                passed_urls += 1
                report.append(f"✅ {name} | {url} | {detail}")
            else:
                failed_urls += 1
                report.append(f"❌ {name} | {url} | {detail}")

        if good_urls:
            output_lines.append(", ".join([name] + good_urls))
            passed_sources += 1
        elif name in local_sources:
            # 上游整组失效时保留本地旧配置，避免一次网络故障把可用源覆盖掉。
            output_lines.append(local_sources[name])
            skipped_sources += 1
            report.append(f"🛡️ {name}：上游全部检测失败，保留本地旧配置")
        else:
            skipped_sources += 1
            report.append(f"⏭️ {name}：上游全部检测失败，跳过新增")

    Path(args.output).write_text("\n".join(output_lines).rstrip() + "\n", encoding="utf-8")
    summary = [
        f"上游源检测：通过 {passed_sources} 组，跳过/保留旧配置 {skipped_sources} 组",
        f"URL 检测：通过 {passed_urls} 条，失败 {failed_urls} 条",
        "",
        *report,
    ]
    Path(args.report).write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    if passed_sources == 0 and not local_sources:
        print("没有任何可用源，终止同步。", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
