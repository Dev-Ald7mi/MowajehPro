#!/usr/bin/env python3
"""
license_gen.py
---------------
مولّد مفاتيح ترخيص لتطبيق لوحة تحكم الراوتر — يطابق نفس خوارزمية التحقق
الموجودة بملف router-control.html (نفس الملح LICENSE_SALT بالضبط).

الاستخدام:
    python3 license_gen.py            # يولّد مفتاح واحد عشوائي
    python3 license_gen.py 5          # يولّد 5 مفاتيح دفعة وحدة

⚠️ تنبيه صادق: هذا تحقق من جهة العميل (Client-side) فقط — أي شخص يفتح
"عرض المصدر" على الصفحة يقدر نظرياً يقرأ نفس الخوارزمية ويولّد مفاتيح بنفسه.
هذا رادع بسيط (Deterrent) وليس حماية حقيقية (DRM) — لو تبي حماية فعلية
لازم تحقق من الخادم (Server-side) بمفتاح سري ما يوصل للعميل أبداً.
"""

import random
import string
import sys

LICENSE_SALT = "RTRCTRL-2026"  # لازم يطابق نفس القيمة بالضبط بملف router-control.html


def checksum(base12: str) -> str:
    h = 0
    for ch in base12 + LICENSE_SALT:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return base36(h % 1679616).rjust(4, "0")


def base36(n: int) -> str:
    digits = string.digits + string.ascii_uppercase
    if n == 0:
        return "0"
    out = ""
    while n:
        n, r = divmod(n, 36)
        out = digits[r] + out
    return out


def gen_one() -> str:
    alphabet = string.ascii_uppercase + string.digits
    base12 = "".join(random.choices(alphabet, k=12))
    key = base12 + checksum(base12)
    return "-".join(key[i:i + 4] for i in range(0, 16, 4))


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    for _ in range(count):
        print(gen_one())
