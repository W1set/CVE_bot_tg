#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import logging
from datetime import datetime, timedelta, timezone

import requests

# ---------------------------------------------------------------- НАСТРОЙКИ

def _require_env(name):
    val = os.environ.get(name)
    if not val:
        raise SystemExit(f"Flase {name}.")
    return val

TELEGRAM_TOKEN = _require_env("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = _require_env("TELEGRAM_CHAT_ID")
NVD_API_KEY = os.environ.get("NVD_API_KEY")        
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")    

POLL_INTERVAL_SEC = 15 * 60   
LOOKBACK_MIN = 20             
MIN_CVSS_TO_ALERT = 0.0      
STATE_FILE = "seen_cves.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cve_bot")

# короткий словарь самых частых CWE -> человекочитаемая категория
CWE_NAMES = {
    "CWE-79": "XSS — межсайтовый скриптинг",
    "CWE-89": "SQL-инъекция",
    "CWE-78": "инъекция команд ОС",
    "CWE-94": "инъекция кода",
    "CWE-22": "обход каталогов (path traversal)",
    "CWE-352": "CSRF",
    "CWE-434": "загрузка произвольных файлов",
    "CWE-287": "некорректная аутентификация",
    "CWE-306": "отсутствие аутентификации",
    "CWE-269": "некорректное управление привилегиями",
    "CWE-284": "некорректный контроль доступа",
    "CWE-862": "отсутствие авторизации",
    "CWE-863": "некорректная авторизация",
    "CWE-200": "утечка информации",
    "CWE-522": "слабая защита учётных данных",
    "CWE-798": "хардкод учётных данных",
    "CWE-476": "разыменование NULL-указателя",
    "CWE-416": "use-after-free",
    "CWE-415": "double free",
    "CWE-119": "ошибка работы с буфером",
    "CWE-120": "переполнение буфера",
    "CWE-787": "запись за границами буфера",
    "CWE-125": "чтение за границами буфера",
    "CWE-190": "переполнение целого числа",
    "CWE-611": "XXE — внедрение внешних XML-сущностей",
    "CWE-918": "SSRF",
    "CWE-502": "небезопасная десериализация",
    "CWE-601": "открытое перенаправление",
    "CWE-732": "некорректные права доступа",
    "CWE-400": "неконтролируемое потребление ресурсов (DoS)",
    "CWE-770": "выделение ресурсов без лимита (DoS)",
    "CWE-295": "некорректная проверка сертификата",
    "CWE-20": "некорректная валидация входных данных",
    "CWE-668": "ресурс доступен не в той области видимости",
    "CWE-843": "type confusion",
    "CWE-362": "race condition",
}

# -------------------------------------------------------------- СОСТОЯНИЕ

def load_seen():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, encoding="utf-8") as f:
            return set(json.load(f))
    return set()

def save_seen(seen):
    # храним не больше 5000 последних ID, чтобы файл не рос бесконечно
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(list(seen)[-5000:], f)

# ---------------------------------------------------------------- NVD API

def fetch_recent_cves():
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=LOOKBACK_MIN)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    r = requests.get(NVD_URL, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json().get("vulnerabilities", [])

def extract_score(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m["cvssData"]
            severity = data.get("baseSeverity") or m.get("baseSeverity", "N/A")
            return data["baseScore"], severity
    return None, "не оценено"

def extract_cwe(weaknesses):
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d["lang"] != "en":
                continue
            cwe_id = d["value"]
            if cwe_id.startswith("NVD-CWE"):
                continue
            name = CWE_NAMES.get(cwe_id)
            return f"{cwe_id} — {name}" if name else cwe_id
    return "категория не указана"

def extract_product(configurations):
    for cfg in configurations or []:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m["criteria"].split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    return f"{vendor} {product}".replace("_", " ")
    return None

# ------------------------------------------------------------ GITHUB SEARCH

def find_poc_repos(cve_id, limit=3):
    try:
        headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
        r = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": cve_id, "sort": "updated"},
            headers=headers, timeout=15,
        )
        r.raise_for_status()
        items = r.json().get("items", [])[:limit]
        return [(it["full_name"], it["html_url"]) for it in items]
    except requests.RequestException:
        return []

# ------------------------------------------------------------------ TELEGRAM

def esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def format_message(cve):
    cve_id = cve["id"]
    desc = next((d["value"] for d in cve["descriptions"] if d["lang"] == "en"), "")
    score, severity = extract_score(cve.get("metrics", {}))
    cwe = extract_cwe(cve.get("weaknesses"))
    product = extract_product(cve.get("configurations"))

    score_line = f"{score} ({severity})" if score is not None else "ещё не оценено"

    lines = [
        f"🆕 <b>{esc(cve_id)}</b>",
        f"📊 Score: <b>{esc(score_line)}</b>",
        f"🏷 Категория: {esc(cwe)}",
    ]
    if product:
        lines.append(f"🎯 Затрагивает: {esc(product)}")
    lines.append(f"\n{esc(desc[:500])}")

    pocs = find_poc_repos(cve_id)
    if pocs:
        lines.append("\n🛠 Возможные PoC/инструменты (GitHub, требует проверки):")
        lines += [f"• <a href=\"{url}\">{esc(name)}</a>" for name, url in pocs]

    lines.append(f"\n🔗 https://nvd.nist.gov/vuln/detail/{cve_id}")
    return "\n".join(lines)[:4000]

def send_telegram(text):
    r = requests.post(TELEGRAM_API, data={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }, timeout=15)
    if not r.ok:
        log.error("Не удалось отправить в Telegram: %s", r.text)

# ----------------------------------------------------------------------- MAIN

def main():
    seen = load_seen()
    log.info("Запуск. Уже отслежено CVE: %d", len(seen))
    while True:
        try:
            for item in fetch_recent_cves():
                cve = item["cve"]
                cve_id = cve["id"]
                if cve_id in seen:
                    continue
                score, _ = extract_score(cve.get("metrics", {}))
                if score is not None and score < MIN_CVSS_TO_ALERT:
                    seen.add(cve_id)
                    save_seen(seen)
                    continue
                send_telegram(format_message(cve))
                seen.add(cve_id)
                save_seen(seen)
                log.info("Отправлено: %s", cve_id)
                time.sleep(1)  
        except requests.RequestException as e:
            log.error("Ошибка запроса: %s", e)
        time.sleep(POLL_INTERVAL_SEC)

if __name__ == "__main__":
    main()
