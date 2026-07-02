#!/usr/bin/env python3
"""Discover Polymarket-related domains and emit Loon rules.

Usage:
  python3 scripts/polymarket_rule_discovery.py static
  python3 scripts/polymarket_rule_discovery.py parse /path/to/tcpdump.log
  sudo tcpdump -i en0 -l -nn -s 0 'port 53 or port 853 or port 443' | python3 scripts/polymarket_rule_discovery.py parse -
"""

from __future__ import annotations

import argparse
import html
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request


SEED_URLS = [
    "https://polymarket.com/",
    "https://polymarket.com/markets",
]

socket.setdefaulttimeout(8)
MAX_ASSETS = 40

KEEP_SUFFIXES = {
    "polymarket.com",
    "polymarket.us",
    "privy.io",
    "walletconnect.org",
    "walletconnect.com",
    "reown.com",
    "alchemy.com",
    "infura.io",
    "moonpay.com",
    "fun.xyz",
    "safe.global",
    "sardine.ai",
    "magic.link",
    "turnkey.com",
    "datadoghq.eu",
    "datadoghq.com",
    "intercom.io",
    "intercomcdn.com",
    "debugbear.com",
    "sentry.io",
    "segment.io",
    "amplitude.com",
    "statsigapi.net",
    "launchdarkly.com",
    "cloudfront.net",
    "amazonaws.com",
}

DROP_SUFFIXES = {
    "schema.org",
    "w3.org",
    "google.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "tiktok.com",
    "x.com",
    "discord.gg",
}

HOST_RE = re.compile(
    r"(?i)\b(?:https?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?::\d+)?"
)
LOOSE_HOST_RE = re.compile(r"(?i)\b([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\.[a-z]{2,})\b")
DNS_QUERY_RE = re.compile(r"(?i)\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\.\s+(?:A|AAAA|HTTPS|SVCB|CNAME)\?")


def fetch(url: str, timeout: int = 8) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 polymarket-rule-discovery",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
        raw = resp.read()
        enc = resp.headers.get_content_charset() or "utf-8"
        return raw.decode(enc, "replace")


def normalize_host(host: str) -> str | None:
    host = html.unescape(host).strip().strip(".").lower()
    host = host.replace("\\u002e", ".")
    host = re.sub(r"[^a-z0-9.-].*$", "", host)
    if not host or "." not in host:
        return None
    try:
        host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = host.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return None
    if host.endswith(".local") or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return None
    return host


def registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_part_tlds = {
        "co.uk",
        "com.au",
        "com.cn",
        "com.hk",
        "com.sg",
        "co.jp",
    }
    tail = ".".join(labels[-2:])
    if tail in two_part_tlds and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


def is_relevant(host: str) -> bool:
    base = registrable(host)
    if base in DROP_SUFFIXES:
        return False
    return base in KEEP_SUFFIXES or "polymarket" in host


def extract_hosts(text: str) -> set[str]:
    text = html.unescape(text)
    text = urllib.parse.unquote(text)
    text = text.replace("\\u002f", "/").replace("\\/", "/")
    text = text.replace("\\u002e", ".")
    hosts = set()
    for regex in (HOST_RE, DNS_QUERY_RE, LOOSE_HOST_RE):
        for match in regex.finditer(text):
            host = normalize_host(match.group(1))
            if host and is_relevant(host):
                hosts.add(host)
    return hosts


def extract_assets(base_url: str, text: str) -> set[str]:
    assets = set()
    for attr in re.finditer(r"""(?i)(?:src|href)=["']([^"']+)["']""", text):
        url = html.unescape(attr.group(1))
        if "_next/" not in url and not url.endswith(".js"):
            continue
        assets.add(urllib.parse.urljoin(base_url, url))
    for path in re.finditer(r"""["']([^"']+/_next/[^"']+\.js[^"']*)["']""", text):
        assets.add(urllib.parse.urljoin(base_url, html.unescape(path.group(1))))
    return assets


def static_discovery() -> set[str]:
    hosts = set()
    seen_assets = set()
    for url in SEED_URLS:
        try:
            text = fetch(url, timeout=10)
        except Exception as exc:
            print(f"# fetch failed {url}: {exc}", file=sys.stderr)
            continue
        hosts |= extract_hosts(text)
        for asset_url in sorted(extract_assets(url, text)):
            if len(seen_assets) >= MAX_ASSETS:
                break
            if asset_url in seen_assets:
                continue
            seen_assets.add(asset_url)
            try:
                asset = fetch(asset_url, timeout=5)
            except Exception:
                continue
            hosts |= extract_hosts(asset)
    return hosts


def collapse_to_suffixes(hosts: set[str]) -> list[str]:
    suffixes = set()
    exact = set()
    for host in hosts:
        base = registrable(host)
        if host.endswith(".cloudfront.net") or host.endswith(".amazonaws.com"):
            exact.add(host)
        else:
            suffixes.add(base)
    lines = [f"DOMAIN-SUFFIX,{suffix}" for suffix in sorted(suffixes)]
    lines += [f"DOMAIN,{host}" for host in sorted(exact)]
    return lines


def parse_stream(stream) -> set[str]:
    hosts = set()
    for line in stream:
        hosts |= extract_hosts(line)
    return hosts


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("static")
    parse_p = sub.add_parser("parse")
    parse_p.add_argument("file", help="tcpdump/netlog text file, or - for stdin")
    args = parser.parse_args()

    if args.cmd == "static":
        hosts = static_discovery()
    else:
        if args.file == "-":
            hosts = parse_stream(sys.stdin)
        else:
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                hosts = parse_stream(fh)

    for line in collapse_to_suffixes(hosts):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
