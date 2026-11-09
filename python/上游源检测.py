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


def read_config(path):
    """读取 api_list.json，返回规范化的 API_LIST / API_MIRRORS。"""
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError("配置根节点必须是 JSON 对象")
    api_list = config.get("API_LIST", [])
    api_mirrors = config.get("API_MIRRORS", {})
    if not isinstance(api_list, list) or not isinstance(api_mirrors, dict):
        raise ValueError("API_LIST 必须是数组，API_MIRRORS 必须是对象")
    return api_list, api_mirrors


def main():
    parser = argparse.ArgumentParser(description="逐条检测上游 TVBox api_list.json")
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--local", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    local_api_list, local_mirrors = read_config(args.local)
    upstream_api_list, upstream_mirrors = read_config(args.upstream)

    local_direct = {}
    for item in local_api_list:
        if isinstance(item, list) and len(item) >= 2 and item[0]:
            local_direct.setdefault(str(item[0]), []).extend(
                str(url).strip() for url in item[1:] if str(url).strip()
            )

    output_api_list = []
    output_mirrors = {}
    report = []
    passed_groups = skipped_groups = passed_urls = failed_urls = 0

    for item in upstream_api_list:
        if not isinstance(item, list) or len(item) < 2:
            report.append(f"⏭️ 忽略格式无效的 API_LIST 条目：{item!r}")
            continue
        name = str(item[0]).strip()
        urls = [str(url).strip() for url in item[1:] if str(url).strip()]
        if not name or not urls:
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
            output_api_list.append([name] + good_urls)
            passed_groups += 1
        else:
            old_urls = local_direct.get(name, [])
            if old_urls:
                output_api_list.append([name] + old_urls)
                skipped_groups += 1
                report.append(f"🛡️ {name}：上游全部检测失败，保留本地旧配置")
            else:
                skipped_groups += 1
                report.append(f"⏭️ {name}：上游全部检测失败，跳过新增")

    for name, urls in upstream_mirrors.items():
        if isinstance(urls, str):
            urls = [urls]
        if not isinstance(urls, list):
            report.append(f"⏭️ {name}：镜像配置格式无效，跳过")
            continue
        good_urls = []
        for url in urls:
            url = str(url).strip()
            if not url:
                continue
            ok, detail = probe(url)
            if ok:
                good_urls.append(url)
                passed_urls += 1
                report.append(f"✅ {name} | {url} | {detail}")
            else:
                failed_urls += 1
                report.append(f"❌ {name} | {url} | {detail}")

        if good_urls:
            output_mirrors[name] = good_urls
            passed_groups += 1
        elif name in local_mirrors:
            output_mirrors[name] = local_mirrors[name]
            skipped_groups += 1
            report.append(f"🛡️ {name}：上游镜像全部检测失败，保留本地旧配置")
        else:
            skipped_groups += 1
            report.append(f"⏭️ {name}：上游镜像全部检测失败，跳过新增")

    output_config = {
        "API_LIST": output_api_list,
        "API_MIRRORS": output_mirrors,
    }
    Path(args.output).write_text(
        json.dumps(output_config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    summary = [
        f"上游源检测：通过 {passed_groups} 组，跳过/保留旧配置 {skipped_groups} 组",
        f"URL 检测：通过 {passed_urls} 条，失败 {failed_urls} 条",
        "",
        *report,
    ]
    Path(args.report).write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    if passed_groups == 0 and not local_api_list and not local_mirrors:
        print("没有任何可用源，终止同步。", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
