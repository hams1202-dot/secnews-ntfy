#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------- USER CONFIG ----------------
NTFY_SERVER = os.getenv("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
# GitHub Actions의 Secret(환경변수)을 우선 사용하고, 내 PC에서 그냥 실행할 땐 기본 토픽을 사용합니다.
NTFY_TOPIC = os.getenv("NTFY_TOPIC", "secnews-kr-1802be6ff15a1c61540f9d23")

FEEDS = {
    "데일리시큐": "https://www.dailysecu.com/rss/allArticle.xml",
    "보안뉴스": "https://www.boannews.com/rss/allArticle.xml",
    "KISA 보호나라": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
}

KEYWORDS = [
    "해킹", "침해사고", "정보유출", "개인정보 유출", "데이터 유출",
    "다크웹", "랜섬웨어", "웹쉘", "악성코드", "악성 ip", "공격 ip",
    "디도스", "서비스 거부", "계정 탈취", "피싱", "제로데이",
    "취약점", "원격 코드 실행", "보안 취약점", "유출", "탈취",
    "cyber attack", "cyberattack", "data breach", "data leak",
    "ransomware", "webshell", "web shell", "dark web", "darknet",
    "zero-day", "zero day", "remote code execution", "rce",
    "critical vulnerability", "actively exploited", "exploited in the wild",
    "malware", "botnet", "credential theft", "initial access",
]

DB_PATH = Path(__file__).with_name("seen_articles.sqlite3")
LOG_PATH = Path(__file__).with_name("ntfy_security_news.log")
MAX_BODY_CHARS = 500
HTTP_TIMEOUT = 20
# ---------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_PATH, encoding="utf-8"), logging.StreamHandler()],
)

def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()

def child_text(element, names):
    for child in list(element):
        if local_name(child.tag) in names:
            return " ".join("".join(child.itertext()).split())
    return ""

def parse_date(value: str) -> str:
    if not value:
        return ""
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return value[:80]

def translate_to_ko(text: str) -> str:
    if not text or re.search(r"[가-힣]", text):
        return text
    try:
        resp = requests.get(
            "https://translate.googleapis.com/translate_a/single",
            params={"client": "gtx", "sl": "auto", "tl": "ko", "dt": "t", "q": text},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10,
            verify=False,
        )
        data = resp.json()
        return "".join(part[0] for part in data[0] if part[0])
    except Exception as e:
        logging.warning("Translation failed: %s", e)
        return text

def fetch_feed(source: str, url: str):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PersonalSecurityNewsNotifier/1.0 (+RSS reader)"},
    )
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as response:
        raw = response.read(4 * 1024 * 1024)
    root = ET.fromstring(raw)
    items = []
    for node in root.iter():
        if local_name(node.tag) not in ("item", "entry"):
            continue
        title = child_text(node, {"title"}) or "(제목 없음)"
        link = ""
        for child in list(node):
            lname = local_name(child.tag)
            if lname == "link":
                href = child.attrib.get("href")
                link = href or (child.text or "").strip()
                if link:
                    break
        summary = child_text(node, {"description", "summary", "content", "encoded"})
        summary = re.sub(r"<[^>]+>", " ", summary)
        pubdate = child_text(node, {"pubdate", "published", "updated", "date"})
        items.append({
            "source": source,
            "title": title,
            "link": link,
            "summary": summary,
            "date": parse_date(pubdate),
        })
    return items

def item_id(item):
    basis = item["link"] or (item["source"] + "|" + item["title"])
    return hashlib.sha256(basis.encode("utf-8", "ignore")).hexdigest()

def matched_keywords(item):
    haystack = (item["title"] + " " + item["summary"]).lower()
    return [kw for kw in KEYWORDS if kw.lower() in haystack]

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS seen (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            first_seen TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn

def already_seen(conn, uid):
    return conn.execute("SELECT 1 FROM seen WHERE id=?", (uid,)).fetchone() is not None

def mark_seen(conn, item):
    conn.execute(
        "INSERT OR IGNORE INTO seen(id, source, title, first_seen) VALUES(?,?,?,?)",
        (item_id(item), item["source"], item["title"], datetime.now(timezone.utc).isoformat()),
    )

def send_ntfy(item, keywords):
    now_str = datetime.now().strftime("%m/%d %H:%M")
    title_header = f"긴급 키워드 감지 · {now_str}"

    ko_title = translate_to_ko(item["title"])
    raw_summary = re.sub(r"\s+", " ", item["summary"]).strip()
    if len(raw_summary) > MAX_BODY_CHARS:
        raw_summary = raw_summary[:MAX_BODY_CHARS] + "…"
    ko_summary = translate_to_ko(raw_summary) if raw_summary else ""

    # 상단 알림창 첫 줄에 기사 제목이 바로 보이도록 배치
    body = f"{ko_title}"
    if ko_summary:
        body += f"\n\n{ko_summary}"
    body += f"\n\n출처: {item['source']} | 키워드: {', '.join(keywords[:5])}"
    if item["link"]:
        body += f"\n원문: {item['link']}"

    payload = {
        "topic": NTFY_TOPIC,
        "title": title_header,
        "message": body,
        "tags": ["rotating_light"],
        "priority": 4,  # 개별 팝업이 잘 뜨도록 높은 우선순위(4: high) 적용
    }
    if item["link"]:
        payload["click"] = item["link"]

    resp = requests.post(
        NTFY_SERVER,
        json=payload,
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    return ko_title

def main():
    conn = db_connect()
    is_first_run = conn.execute("SELECT COUNT(*) FROM seen").fetchone()[0] == 0
    new_count = 0
    for source, url in FEEDS.items():
        try:
            items = fetch_feed(source, url)
            logging.info("%s: %d items", source, len(items))
            for item in reversed(items):
                uid = item_id(item)
                if already_seen(conn, uid):
                    continue
                kws = matched_keywords(item)
                if not is_first_run and kws:
                    try:
                        ko_t = send_ntfy(item, kws)
                        logging.info("SENT [%s] %s", source, ko_t)
                        # 휴대폰에서 개별 알림으로 분리되어 울리도록 1.5초 대기
                        time.sleep(1.5)
                    except Exception:
                        logging.exception("ntfy send failed; item will be retried next run")
                        continue
                mark_seen(conn, item)
                new_count += 1
            conn.commit()
        except Exception:
            logging.exception("Feed failed: %s (%s)", source, url)
    if is_first_run:
        logging.info("First run: existing feed entries seeded; no old alerts sent.")
    logging.info("Finished. New feed items recorded: %d", new_count)
    conn.close()

if __name__ == "__main__":
    main()