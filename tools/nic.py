#!/usr/bin/env python3
"""Клиент RU-CENTER (nic.ru) DNS API. Только stdlib.

Учётные данные берутся из окружения:
  NIC_CLIENT_ID, NIC_CLIENT_SECRET, NIC_USERNAME, NIC_PASSWORD

Команды:
  token                         получить и показать статус токена
  domains                       домены договора: NS, DNSSEC, флаги
  services                      все услуги договора: сроки и автопродление
  dnscheck [DOMAIN ...]         проверить DNS доменов: MX, SPF, DMARC, CAA
  expiring [DAYS]               услуги на исходе (по умолчанию 90 дней)
  dns-services                  список услуг DNS-хостинга (раздел dns-master)
  zones [SERVICE]               зоны (по всем услугам или по одной)
  zone SERVICE ZONE             содержимое зоны в формате BIND
  records SERVICE ZONE          записи зоны списком (id, тип, имя, значение)
  add SERVICE ZONE TYPE NAME VALUE [--prio N] [--ttl N]
  delete SERVICE ZONE RECORD_ID
  commit SERVICE ZONE           применить отложенные изменения зоны
  rollback SERVICE ZONE         отменить неприменённые изменения
  raw METHOD PATH [BODY]        произвольный запрос к API

Изменения (add/delete) не вступают в силу до commit.
"""

import os
import sys
import json
import datetime
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET

API = "https://api.nic.ru"
TOKEN_URL = f"{API}/oauth/token"
NS = {"n": "http://www.nic.ru/ns/rest/1.0"}
TOKEN_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".nic_token.json")

# Права токена. dns-master — на чтение и запись, остальные разделы — только чтение.
# Пути указываются регулярками, поэтому раздел перечисляется дважды: сам путь
# (/domains) и всё, что под ним (/domains/...).
DEFAULT_SCOPE = " ".join([
    "GET:/dns-master/.+", "PUT:/dns-master/.+", "POST:/dns-master/.+", "DELETE:/dns-master/.+",
    "GET:/domains", "GET:/domains/.+",
    "GET:/services", "GET:/services/.+",
])
SCOPE = os.environ.get("NIC_SCOPE", DEFAULT_SCOPE)


class ApiError(Exception):
    pass


def _env(name):
    value = os.environ.get(name)
    if not value:
        raise ApiError(f"не задана переменная окружения {name}")
    return value


def get_token(force=False):
    # Кэш хранит scope: если права расширили, старый токен уже не подходит
    # и его надо перевыпустить, иначе запросы к новым разделам дадут 403.
    if not force and os.path.exists(TOKEN_CACHE):
        with open(TOKEN_CACHE) as fh:
            cached = json.load(fh)
        if cached.get("access_token") and cached.get("scope") == SCOPE:
            return cached["access_token"]

    data = urllib.parse.urlencode({
        "grant_type": "password",
        "username": _env("NIC_USERNAME"),
        "password": _env("NIC_PASSWORD"),
        "client_id": _env("NIC_CLIENT_ID"),
        "client_secret": _env("NIC_CLIENT_SECRET"),
        "scope": SCOPE,
    }).encode()

    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        raise ApiError(f"не удалось получить токен: HTTP {exc.code} {exc.read().decode(errors='replace')}")

    payload["scope"] = SCOPE
    with open(TOKEN_CACHE, "w") as fh:
        json.dump(payload, fh)
    os.chmod(TOKEN_CACHE, 0o600)
    return payload["access_token"]


def call(method, path, body=None, retry=True):
    token = get_token()
    req = urllib.request.Request(
        API + path,
        data=body.encode() if body else None,
        method=method,
    )
    req.add_header("Authorization", f"Bearer {token}")
    if body:
        req.add_header("Content-Type", "application/xml")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as exc:
        if exc.code == 401 and retry:
            get_token(force=True)
            return call(method, path, body, retry=False)
        raise ApiError(f"{method} {path} → HTTP {exc.code}\n{exc.read().decode(errors='replace')}")


def parse(xml_text):
    return ET.fromstring(xml_text)


def cmd_token(_args):
    get_token(force=True)
    print("токен получен, кэш:", TOKEN_CACHE)


def cmd_domains(_args):
    # Разделы /domains и /services отвечают JSON, в отличие от dns-master.
    data = json.loads(call("GET", "/domains"))["data"]
    for dom in data.get("domain", []):
        ns = ", ".join(n["name"] for n in dom.get("nameservers", [])) or "не делегирован"
        flags = ", ".join(k for k, v in (dom.get("flags") or {}).items() if v) or "-"
        print("{:<24} DNSSEC: {:<4} NS: {}".format(
            dom.get("idn_domain") or dom.get("domain", "?"),
            "да" if dom.get("dnssec") else "нет",
            ns,
        ))
        print("{:<24} флаги: {}".format("", flags))


def cmd_all_services(_args):
    data = json.loads(call("GET", "/services"))["data"]
    svcs = sorted(data.get("service", []), key=lambda s: s.get("expiry_date") or "9999")
    row = "{:<18} {:<24} {:<9} {:<12} {}"
    print(row.format("НАЗВАНИЕ", "ТИП", "СТАТУС", "ИСТЕКАЕТ", "АВТОПРОДЛЕНИЕ"))
    for svc in svcs:
        print(row.format(
            svc.get("name", "?"),
            (svc.get("current_period") or {}).get("service_type", "-"),
            svc.get("status", "-"),
            svc.get("expiry_date") or "-",
            "да" if svc.get("autorenew") else "НЕТ",
        ))


def _resolve(name, rtype):
    """Запрос к публичному резолверу через DNS-over-HTTPS.

    Зоны этого договора живут не в dns-master, а на облачной платформе, которую
    API не отдаёт. Фактическое состояние DNS видно только снаружи.
    """
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            payload = json.load(resp)
    except Exception as exc:
        raise ApiError(f"резолвер недоступен ({exc}); нужен доступ к dns.google")
    if payload.get("Status") == 3:
        return []
    return [a["data"] for a in payload.get("Answer", [])]


def _domain_names():
    data = json.loads(call("GET", "/domains"))["data"]
    return [d.get("idn_domain") or d["domain"].lower() for d in data.get("domain", [])]


def cmd_dnscheck(args):
    for dom in args or _domain_names():
        print("=" * 64)
        print(dom)
        print("=" * 64)

        a = _resolve(dom, "A")
        mx = _resolve(dom, "MX")
        txt = _resolve(dom, "TXT")
        dmarc = _resolve(f"_dmarc.{dom}", "TXT")
        caa = _resolve(dom, "CAA")
        spf = [t for t in txt if "v=spf1" in t]

        print("  A      ", ", ".join(a) or "—")
        print("  MX     ", ", ".join(mx) or "—")
        print("  SPF    ", ", ".join(spf) or "—")
        print("  DMARC  ", ", ".join(dmarc) or "—")
        print("  CAA    ", ", ".join(caa) or "—")

        problems = []

        # Лишний пробел в начале TXT ломает запись молча: и SPF, и DMARC
        # опознаются по префиксу версии, а с пробелом префикс не совпадает.
        for label, values, prefix in (("SPF", spf, "v=spf1"), ("DMARC", dmarc, "v=DMARC1")):
            for value in values:
                bare = value.strip('"')
                if bare != bare.strip():
                    problems.append(f"{label}: лишний пробел по краям записи — она не опознаётся")
                elif not bare.startswith(prefix):
                    problems.append(f"{label}: запись не начинается с {prefix} — игнорируется")

        if not a and not mx:
            problems.append("зона пустая: нет ни сайта, ни почты")
        if mx and not spf:
            problems.append("есть MX, но нет SPF — письма будут падать в спам")
        if mx and not dmarc:
            problems.append("есть почта, но нет DMARC — домен можно подделывать")
        if not mx and any("mail" in t.lower() for t in txt):
            problems.append("следы почтовой настройки без MX")
        if not caa:
            problems.append("нет CAA — сертификат может выпустить любой УЦ")

        print("  " + "-" * 60)
        if problems:
            for p in problems:
                print("  ! " + p)
        else:
            print("  замечаний нет")
        print()


def cmd_expiring(args):
    limit = int(args[0]) if args else 90
    data = json.loads(call("GET", "/services"))["data"]
    today = datetime.date.today()
    rows = []
    for svc in data.get("service", []):
        raw = svc.get("expiry_date")
        if not raw:
            continue
        left = (datetime.date.fromisoformat(raw) - today).days
        if left <= limit:
            rows.append((left, svc))
    if not rows:
        print(f"в ближайшие {limit} дней ничего не истекает")
        return
    for left, svc in sorted(rows):
        print("{:<18} истекает {} (через {} дн.) автопродление: {}".format(
            svc.get("name", "?"),
            svc.get("expiry_date"),
            left,
            "да" if svc.get("autorenew") else "НЕТ",
        ))


def cmd_dns_services(_args):
    root = parse(call("GET", "/dns-master/services"))
    for svc in root.iterfind(".//n:service", NS):
        print("{:<20} домены: {:<4} зоны: {:<4} {}".format(
            svc.get("name", "?"),
            svc.get("domains-limit", "-"),
            svc.get("domains-num", "-"),
            svc.get("payer", ""),
        ))


def cmd_zones(args):
    path = f"/dns-master/services/{args[0]}/zones" if args else "/dns-master/zones"
    root = parse(call("GET", path))
    for zone in root.iterfind(".//n:zone", NS):
        print("{:<35} услуга: {:<18} изменения: {}".format(
            zone.get("name", "?"),
            zone.get("service", "-"),
            "есть" if zone.get("has-changes") == "true" else "нет",
        ))


def cmd_zone(args):
    service, zone = args[0], args[1]
    print(call("GET", f"/dns-master/services/{service}/zones/{zone}"))


def cmd_records(args):
    service, zone = args[0], args[1]
    root = parse(call("GET", f"/dns-master/services/{service}/zones/{zone}/records"))
    for rec in root.iterfind(".//n:rr", NS):
        name = rec.findtext("n:name", "?", NS)
        rtype = rec.findtext("n:type", "?", NS)
        value = "".join(rec.find(f"n:{rtype.lower()}", NS).itertext()).strip() \
            if rec.find(f"n:{rtype.lower()}", NS) is not None else ""
        print("{:<10} {:<7} {:<30} {}".format(rec.get("id", "-"), rtype, name, " ".join(value.split())))


def _record_xml(rtype, name, value, prio=None, ttl=None):
    rtype = rtype.upper()
    ttl_attr = f"<ttl>{ttl}</ttl>" if ttl else ""
    if rtype == "A":
        payload = f"<A>{value}</A>"
    elif rtype == "AAAA":
        payload = f"<AAAA>{value}</AAAA>"
    elif rtype == "CNAME":
        payload = f"<CNAME><name>{value}</name></CNAME>"
    elif rtype == "MX":
        payload = f"<MX><preference>{prio or 10}</preference><exchange><name>{value}</name></exchange></MX>"
    elif rtype == "TXT":
        payload = f"<TXT><string>{value}</string></TXT>"
    elif rtype == "NS":
        payload = f"<NS><name>{value}</name></NS>"
    elif rtype == "SRV":
        raise ApiError("SRV собирается вручную — используй raw")
    else:
        raise ApiError(f"тип {rtype} не поддержан, используй raw")
    return (
        '<?xml version="1.0" encoding="UTF-8" ?>'
        '<request><rr-list>'
        f'<rr><name>{name}</name>{ttl_attr}<type>{rtype}</type>{payload}</rr>'
        '</rr-list></request>'
    )


def cmd_add(args):
    service, zone, rtype, name, value = args[:5]
    opts = args[5:]
    prio = ttl = None
    for i, opt in enumerate(opts):
        if opt == "--prio":
            prio = opts[i + 1]
        elif opt == "--ttl":
            ttl = opts[i + 1]
    body = _record_xml(rtype, name, value, prio, ttl)
    print(call("PUT", f"/dns-master/services/{service}/zones/{zone}/records", body))
    print("\n→ запись добавлена в черновик. Применить: commit", service, zone)


def cmd_delete(args):
    service, zone, rec_id = args[0], args[1], args[2]
    print(call("DELETE", f"/dns-master/services/{service}/zones/{zone}/records/{rec_id}"))
    print("\n→ удаление в черновике. Применить: commit", service, zone)


def cmd_commit(args):
    print(call("POST", f"/dns-master/services/{args[0]}/zones/{args[1]}/commit"))


def cmd_rollback(args):
    print(call("POST", f"/dns-master/services/{args[0]}/zones/{args[1]}/rollback"))


def cmd_raw(args):
    method, path = args[0].upper(), args[1]
    body = args[2] if len(args) > 2 else None
    print(call(method, path, body))


COMMANDS = {
    "token": cmd_token,
    "domains": cmd_domains,
    "services": cmd_all_services,
    "dnscheck": cmd_dnscheck,
    "expiring": cmd_expiring,
    "dns-services": cmd_dns_services,
    "zones": cmd_zones,
    "zone": cmd_zone,
    "records": cmd_records,
    "add": cmd_add,
    "delete": cmd_delete,
    "commit": cmd_commit,
    "rollback": cmd_rollback,
    "raw": cmd_raw,
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        return 1
    try:
        COMMANDS[sys.argv[1]](sys.argv[2:])
    except ApiError as exc:
        print("Ошибка:", exc, file=sys.stderr)
        return 2
    except IndexError:
        print("Не хватает аргументов. См. справку:\n", __doc__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
