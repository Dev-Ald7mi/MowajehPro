#!/usr/bin/env python3
"""
router_proxy.py
----------------
وسيط محلي (Local Proxy) يشغّله المستخدم على جهازه، يتحدث مباشرة مع الراوتر
(هواوي / ZTE / تي بي لينك) عبر الشبكة المحلية، ويعرض النتائج كـ JSON بسيط
مع رؤوس CORS مفتوحة، حتى تقدر صفحة الداشبورد (router-control.html) تقرأها
من المتصفح مباشرة بدون مشاكل حجب المتصفح (CORS / Private Network Access).

التشغيل:
    pip install flask flask-cors requests
    python router_proxy.py

بعدها افتح router-control.html وفعّل "الاتصال الحقيقي" من الإعدادات،
وحدد نوع الراوتر + IP + كلمة المرور.

ملاحظات مهمة:
- هواوي وZTE مدعومين فعلياً (قراءة الإشارة + قفل الباند).
- تي بي لينك: أغلب أجهزة الجوّال/الراوتر عندها بروتوكول تشفير خاص (RSA+AES)
  غير موثّق بشكل ثابت لكل الموديلات، فحالياً مدعوم فقط "فحص الاتصال" الأساسي.
  إذا تعطيني موديلك بالضبط أقدر أحاول أضيف دعم أعمق له.
"""

import base64
import hashlib
import re
import xml.etree.ElementTree as ET

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
# يسمح لأي أصل (الصفحة اللي تفتحها من claude.ai أو محليًا) يتواصل مع هذا البروكسي
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

TIMEOUT = 5


@app.after_request
def add_pna_header(resp):
    # مطلوب من متصفحات كروم الحديثة (Private Network Access) عشان تسمح
    # لصفحة "عامة" بمناداة سيرفر على الشبكة المحلية (localhost يعتبر آمن غالبًا لكن نضيفها للأمان)
    resp.headers["Access-Control-Allow-Private-Network"] = "true"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


def huawei_device_info(ip):
    root = huawei_get_xml(ip, "/api/device/information")
    d = {c.tag: c.text for c in root}
    try:
        plmn_root = huawei_get_xml(ip, "/api/net/current-plmn")
        plmn = {c.tag: c.text for c in plmn_root}
    except Exception:
        plmn = {}
    return {
        "device": d.get("DeviceName", "--"),
        "firmware": d.get("SoftwareVersion", "--"),
        "network": plmn.get("FullName") or plmn.get("ShortName") or "--",
        "uptime": "--",
    }


# ============================================================= HUAWEI =====

def huawei_get_xml(ip, path):
    r = requests.get(f"http://{ip}{path}", timeout=TIMEOUT)
    r.raise_for_status()
    return ET.fromstring(r.text)


def huawei_signal(ip):
    root = huawei_get_xml(ip, "/api/device/signal")
    d = {c.tag: c.text for c in root}
    return {
        "band": d.get("band", "--"),
        "pci": d.get("pci", "--"),
        "rsrp": d.get("rsrp", "--"),
        "rsrq": d.get("rsrq", "--"),
        "sinr": d.get("sinr", d.get("rssi", "--")),
        "cell_id": d.get("cell_id", "--"),
        "mode": d.get("mode", "--"),
    }


def huawei_login_and_token(ip, password, username="admin"):
    tok_root = huawei_get_xml(ip, "/api/webserver/SesTokInfo")
    tok_map = {c.tag: c.text for c in tok_root}
    token = tok_map.get("TokInfo")
    ses_cookie = None
    ses_info = tok_map.get("SesInfo", "")
    m = re.search(r"SessionID=([^;]+)", ses_info)
    if m:
        ses_cookie = "SessionID=" + m.group(1)

    def sha256hex(s):
        return hashlib.sha256(s.encode()).hexdigest()

    b64pwd = base64.b64encode(sha256hex(password).encode()).decode()
    final_pwd = base64.b64encode(sha256hex(username + b64pwd + token).encode()).decode()

    headers = {
        "Content-Type": "text/xml",
        "__RequestVerificationToken": token,
        "Cookie": ses_cookie or "",
    }
    body = (f"<?xml version='1.0' encoding='UTF-8'?>"
            f"<request><Username>{username}</Username>"
            f"<Password>{final_pwd}</Password><password_type>4</password_type></request>")
    r = requests.post(f"http://{ip}/api/user/login", data=body, headers=headers, timeout=TIMEOUT)
    new_token = r.headers.get("__requestverificationtoken", token)
    return ses_cookie, new_token


def huawei_set_band_lock(ip, password, band_value, network_mode="03"):
    """band_value: قيمة الباند بصيغة هواوي hex bitmask (تختلف حسب الموديل)."""
    ses_cookie, token = huawei_login_and_token(ip, password)
    headers = {"Content-Type": "text/xml", "__RequestVerificationToken": token, "Cookie": ses_cookie or ""}
    body = (f"<?xml version='1.0' encoding='UTF-8'?>"
            f"<request><NetworkMode>{network_mode}</NetworkMode>"
            f"<NetworkBand>{band_value}</NetworkBand><LTEBand>{band_value}</LTEBand></request>")
    r = requests.post(f"http://{ip}/api/net/net-mode", data=body, headers=headers, timeout=TIMEOUT)
    return r.status_code == 200 and "OK" in r.text


def zte_device_info(ip):
    d = zte_get(ip, "wa_inner_version,network_provider,ppp_status")
    return {
        "device": "ZTE",
        "firmware": d.get("wa_inner_version", "--"),
        "network": d.get("network_provider", "--"),
        "uptime": "--",
    }


# ================================================================ ZTE =====

def zte_get(ip, cmd, extra=None):
    params = {"isTest": "false", "cmd": cmd, "multi_data": "1"}
    if extra:
        params.update(extra)
    r = requests.get(f"http://{ip}/goform/goform_get_cmd_process", params=params,
                      headers={"Referer": f"http://{ip}/index.html"}, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()


def zte_signal(ip):
    cmds = ("network_type,signalbar,lte_rsrp,lte_rsrq,lte_snr,lte_rssi,cell_id,"
            "wan_active_band,Z5g_rsrp,Z5g_SINR,nr5g_action_band,nr5g_pci,lte_pci,"
            "wan_lte_ca,lte_ca_pcell_bandwidth")
    d = zte_get(ip, cmds)
    return {
        "band": d.get("wan_active_band", "--"),
        "pci": d.get("lte_pci", "--"),
        "rsrp": d.get("lte_rsrp", "--"),
        "rsrq": d.get("lte_rsrq", "--"),
        "sinr": d.get("lte_snr", "--"),
        "cell_id": d.get("cell_id", "--"),
        "mode": d.get("network_type", "--"),
        "nr_band": d.get("nr5g_action_band", "--"),
        "nr_rsrp": d.get("Z5g_rsrp", "--"),
        "ca": d.get("wan_lte_ca", "--"),
    }


def zte_login(ip, password):
    enc = base64.b64encode(base64.b64encode(password.encode())).decode()
    r = requests.post(f"http://{ip}/goform/goform_set_cmd_process",
                       data={"isTest": "false", "goformId": "LOGIN", "password": enc},
                       headers={"Referer": f"http://{ip}/index.html"}, timeout=TIMEOUT)
    return r.json().get("result") == "3", r.cookies


def zte_set_band_lock(ip, password, band_value):
    ok, cookies = zte_login(ip, password)
    if not ok:
        return False, "فشل تسجيل الدخول — تأكد من كلمة المرور"
    r = requests.post(f"http://{ip}/goform/goform_set_cmd_process",
                       data={"isTest": "false", "goformId": "SET_LTE_BAND_LOCK", "lte_band_lock": band_value},
                       cookies=cookies, headers={"Referer": f"http://{ip}/index.html"}, timeout=TIMEOUT)
    return r.status_code == 200, r.text


# ============================================================ TP-LINK =====

def tplink_reachable(ip):
    try:
        r = requests.get(f"http://{ip}/", timeout=TIMEOUT)
        return r.status_code < 500
    except Exception:
        return False


# =============================================================== API ======

def fiber_reachable(ip):
    """يتأكد بس إن الراوتر موجود ويرد على الشبكة — ما يقرأ بيانات فعلية لأن
    فيرموير A300 (سلام) غير موثّق علنياً، فهذا فحص اتصال أساسي بس حالياً."""
    try:
        r = requests.get(f"http://{ip}/", timeout=TIMEOUT)
        return r.status_code < 500
    except Exception:
        return False


@app.route("/")
def serve_dashboard():
    """يعرض ملف router-control.html مباشرة — افتح http://localhost:5787 بالمتصفح
    بدل فتح الملف نفسه، عشان تتجنب حجب كروم لطلبات fetch من صفحات file://."""
    import os
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "router-control.html")
    if not os.path.exists(html_path):
        return ("ملف router-control.html غير موجود بنفس مجلد router_proxy.py — "
                "انسخه لنفس المجلد (~) وأعد تشغيل السيرفر.", 404)
    with open(html_path, encoding="utf-8") as f:
        return f.read()


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 9100: "Printer",
}
MAX_PORTS_PER_SCAN = 300


def scan_one_port(host, port, timeout=0.6):
    import socket as sockmod
    s = sockmod.socket(sockmod.AF_INET, sockmod.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((host, port))
        return port, result == 0
    except Exception:
        return port, False
    finally:
        s.close()


@app.route("/api/portscan", methods=["POST"])
def api_portscan():
    import concurrent.futures

    body = request.get_json(force=True, silent=True) or {}
    host = body.get("host", "").strip()
    mode = body.get("mode", "quick")  # quick | range
    if not host:
        return jsonify({"ok": False, "error": "أدخل عنوان IP"}), 400

    if mode == "quick":
        ports = sorted(COMMON_PORTS.keys())
    else:
        try:
            start, end = int(body.get("start", 1)), int(body.get("end", 1024))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "نطاق منافذ غير صحيح"}), 400
        if start < 1 or end > 65535 or start > end:
            return jsonify({"ok": False, "error": "نطاق غير صحيح (1-65535)"}), 400
        if (end - start + 1) > MAX_PORTS_PER_SCAN:
            return jsonify({"ok": False, "error": f"أقصى عدد منافذ بالفحص الواحد {MAX_PORTS_PER_SCAN} — قلّل النطاق"}), 400
        ports = list(range(start, end + 1))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
        futures = [pool.submit(scan_one_port, host, p) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                results.append({"port": port, "service": COMMON_PORTS.get(port, "--")})
    results.sort(key=lambda r: r["port"])
    return jsonify({"ok": True, "host": host, "scanned": len(ports), "open_ports": results})


@app.route("/api/ssh/exec", methods=["POST"])
def api_ssh_exec():
    try:
        import paramiko
    except ImportError:
        return jsonify({"ok": False, "error": "مكتبة paramiko غير مثبتة — شغّل: pip install paramiko"}), 500

    body = request.get_json(force=True, silent=True) or {}
    host = body.get("host", "")
    port = int(body.get("port") or 22)
    username = body.get("username", "")
    password = body.get("password", "")
    command = body.get("command", "")
    if not host or not username or not command:
        return jsonify({"ok": False, "error": "بيانات ناقصة (المضيف/المستخدم/الأمر)"}), 400

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=8, banner_timeout=8)
        stdin, stdout, stderr = client.exec_command(command, timeout=12)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        return jsonify({"ok": True, "output": out, "error_output": err, "exit_code": exit_code})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502
    finally:
        client.close()


@app.route("/api/fiber/status")
def api_fiber_status():
    ip = request.args.get("ip")
    ok = fiber_reachable(ip)
    return jsonify({"ok": ok, "data": {"uptime": "--", "firmware": "--"},
                     "error": None if ok else "الراوتر ما يرد على هذا الـ IP"})


@app.route("/api/fiber/wifi")
def api_fiber_wifi():
    return jsonify({"ok": False, "error": "قراءة/تعديل الواي فاي غير مدعومة بعد — نحتاج نشوف صفحة إعدادات الواي فاي الفعلية بالراوتر أول"}), 200


@app.route("/api/fiber/devices")
def api_fiber_devices():
    return jsonify({"ok": False, "data": [], "error": "قائمة الأجهزة غير مدعومة بعد لهذا الفيرموير"}), 200


@app.route("/api/fiber/reboot", methods=["POST"])
def api_fiber_reboot():
    return jsonify({"ok": False, "error": "إعادة التشغيل غير مفعّلة بعد — نحتاج نعرف رابط الأمر الصحيح من واجهة الراوتر"}), 200


@app.route("/api/status")
def api_status():
    vendor = request.args.get("vendor")
    ip = request.args.get("ip")
    try:
        if vendor == "huawei":
            return jsonify({"ok": True, "vendor": vendor, "data": huawei_signal(ip)})
        if vendor == "zte":
            return jsonify({"ok": True, "vendor": vendor, "data": zte_signal(ip)})
        if vendor == "tplink":
            reachable = tplink_reachable(ip)
            return jsonify({"ok": reachable, "vendor": vendor,
                             "data": {}, "note": "تي بي لينك: قراءة تفصيلية للإشارة غير مدعومة حالياً"})
        return jsonify({"ok": False, "error": "نوع راوتر غير معروف"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/device")
def api_device():
    vendor = request.args.get("vendor")
    ip = request.args.get("ip")
    try:
        if vendor == "huawei":
            return jsonify({"ok": True, "data": huawei_device_info(ip)})
        if vendor == "zte":
            return jsonify({"ok": True, "data": zte_device_info(ip)})
        return jsonify({"ok": False, "error": "غير مدعوم لهذا النوع بعد"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


@app.route("/api/lock", methods=["POST"])
def api_lock():
    body = request.get_json(force=True)
    vendor, ip, password, band = body.get("vendor"), body.get("ip"), body.get("password"), body.get("band")
    try:
        if vendor == "huawei":
            ok = huawei_set_band_lock(ip, password, band)
            return jsonify({"ok": ok})
        if vendor == "zte":
            ok, msg = zte_set_band_lock(ip, password, band)
            return jsonify({"ok": ok, "message": msg})
        return jsonify({"ok": False, "error": "قفل الباند غير مدعوم بعد لهذا النوع"}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 502


if __name__ == "__main__":
    print("🚀 Router Proxy يعمل على http://localhost:5787")
    app.run(host="0.0.0.0", port=5787, debug=False)
