# -*- coding: utf-8 -*-
"""Build the static site: guides/<slug>/index.html from content.py + the captures.
Run from the repo root:  python3 -I tools/build.py"""
import base64, html, json, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from decode import load, tcp_checks
from content import GUIDES, L, ETH_TABLE, PIGGY, TELNET_REPORT

CAP = os.path.join(ROOT, "captures")
E = html.escape
WP = "https://fahadnetlab.wordpress.com"

frames_cache = {}
def frames(key):
    if key not in frames_cache:
        frames_cache[key] = load(os.path.join(CAP, key + ".pcapng"))
    return frames_cache[key]

def S(fr, n):
    return fr[n - 1]["s"]

def find(fr, **kw):
    return [f["s"] for f in fr if all((f["s"].get(k) == v) if not callable(v) else v(f["s"].get(k)) for k, v in kw.items())]

def fref(n, cap=None):
    c = f' data-cap="{cap}"' if cap else ""
    return f'<button class="fref" data-frame="{n}"{c} type="button">الإطار {n}</button>'

def first_line(t, n=46):
    t = (t or "").split("\r\n")[0].strip()
    return t if len(t) <= n else t[:n - 1] + "…"

# ------------------------------------------------------------------ what each capture shows
def findings_ftp():
    fr = frames("ftp"); R = []
    syn = find(fr, flags="SYN", dport=21)[0]; sa = find(fr, flags="SYN ACK", sport=21)[0]
    R.append(("المصافحة الثلاثية", f"SYN يبدأ بـ Seq {syn['seq']}، والخادم يرد بـ Ack {sa['ack']}، أي {syn['seq']} + 1.", [syn['no'], sa['no']]))
    for s in [f["s"] for f in fr if (f["s"].get("payload_txt") or "").startswith("227")]:
        t = s["payload_txt"]; m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", t)
        p1, p2 = int(m.group(5)), int(m.group(6)); port = p1 * 256 + p2
        syn2 = find(fr, flags="SYN", dport=port)
        R.append((f"منفذ البيانات {port}", f"<code>{E(t.strip())}</code><br>{p1} × 256 + {p2} = <b>{port}</b>، وفي الإطار التالي يفتح العميل اتصالًا جديدًا على هذا المنفذ.", [s['no']] + ([syn2[0]['no']] if syn2 else [])))
    lst = [f["s"] for f in fr if f["s"].get("sport") == 49672 and f["s"].get("plen", 0) > 0]
    if lst:
        R.append(("قائمة الملفات", f"قناة البيانات حملت {lst[0]['plen']} بايت: <code>{E(lst[0]['payload_txt'].strip())}</code>", [lst[0]['no']]))
    retr = find(fr, payload_txt=lambda v: bool(v) and v.startswith("RETR")); size = find(fr, payload_txt=lambda v: bool(v) and v.startswith("213"))
    if retr:
        R.append(("تحميل ملف فارغ", f"<code>{E(retr[0]['payload_txt'].strip())}</code> بعد رد SIZE <code>{E(size[0]['payload_txt'].strip())}</code>، فانفتح اتصال البيانات وانقفل بدون بيانات.", [size[0]['no'], retr[0]['no']]))
    pw = find(fr, payload_txt=lambda v: bool(v) and v.startswith("PASS"))[0]
    R.append(("كلمة المرور مكشوفة", f"<code>{E(pw['payload_txt'].strip())}</code> تمر نصًا واضحًا. في الدخول المجهول هي بريد شكلي، لكن أي حساب حقيقي ينكشف بنفس الطريقة.", [pw['no']]))
    return R

def findings_bulk():
    fr = frames("ftp-bulk"); R = []
    size = find(fr, payload_txt=lambda v: bool(v) and v.startswith("213"))[0]; retr = find(fr, payload_txt=lambda v: bool(v) and v.startswith("RETR"))[0]
    R.append(("الحجم قبل التحميل", f"<code>{E(retr['payload_txt'].strip())}</code> سبقه SIZE، والرد <code>{E(size['payload_txt'].strip())}</code>.", [size['no'], retr['no']]))
    big = max((f["s"] for f in fr if f["s"].get("proto") == "TCP"), key=lambda s: s["plen"])
    ack = find(fr, ack=big["seq"] + big["plen"], dport=big["sport"])[0]
    R.append(("الملف كله في إطار واحد", f"{big['length']} بايت، منها {big['plen']} بيانات تبدأ من Seq {big['seq']}. العميل يرد بـ Ack {ack['ack']} = {big['seq']} + {big['plen']}.", [big['no'], ack['no']]))
    if big.get("tso"):
        R.append(("لماذا Total Length = 0؟", "الالتقاط تم على الخادم نفسه. نظام التشغيل يسلّم بطاقة الشبكة كتلة كبيرة، والبطاقة هي التي تقسمها لمقاطع بحجم MSS وتكتب الطول (TCP Segmentation Offload). Wireshark رأى الكتلة قبل التقسيم.", [big['no']]))
    rst = find(fr, flags=lambda v: bool(v) and "RST" in v)
    if rst:
        R.append(("الإغلاق", f"الخادم ينهي قناة البيانات بـ FIN، والعميل يقطعها بـ {rst[-1]['flags']}.", [rst[-1]['no']]))
    return R

def findings_smtp():
    fr = frames("smtp"); R = []
    p = find(fr, payload_txt=lambda v: bool(v) and v.startswith("334"))
    R.append(("Base64 ليس تشفيرًا", "الخادم يطلب البيانات بنصوص مشفرة ظاهريًا: " + "، ".join(f"<code>{E(s['payload_txt'][4:].strip())}</code> = <code>{E(base64.b64decode(s['payload_txt'][4:].strip()).decode())}</code>" for s in p) + ". والعميل يرد بنفس الطريقة، فاسم المستخدم وكلمة المرور تُفك فورًا.", [s['no'] for s in p]))
    mf = find(fr, payload_txt=lambda v: bool(v) and v.startswith("MAIL FROM"))[0]
    data = [f["s"] for f in fr if f["s"].get("dport") == 587 and f["s"].get("plen", 0) > 100][0]
    rt = find(fr, payload_txt=lambda v: bool(v) and v.startswith("+OK 529"))[0]
    R.append(("403 بايت أرسلت، 529 وصلت", f"<code>{E(mf['payload_txt'].strip())}</code>، والرسالة في إطار واحد طوله {data['plen']} بايت. وعند الاستلام: <code>+OK 529 octets</code>. الفرق هو ترويسات Return-Path و Received التي أضافها الخادم.", [mf['no'], data['no'], rt['no']]))
    rows = tcp_checks(fr)
    rx = []
    for r in rows:
        if r["seq_status"] == "retx":
            prev = [x for x in rows if x["no"] < r["no"] and x["dir"] == r["dir"] and x["seq"] == r["seq"] and x["len"] > 0]
            rx.append((prev[-1]["no"] if prev else None, r["no"], r["seq"]))
    if rx:
        R.append((f"{len(rx)} إعادات إرسال حقيقية", "نفس البايتات انرسلت مرتين بنفس رقم التسلسل: " + "، ".join(f"الإطار {a} ثم {b}" for a, b, _ in rx) + ".", [n for a, b, _ in rx for n in (a, b) if n]))
    return R

def findings_arp():
    fr = frames("icmp-arp"); R = []
    a1, a2 = S(fr, 1), S(fr, 2)
    R.append(("سؤال للجميع وجواب مباشر", f"{E(a1['info'])} يخرج إلى ff:ff:ff:ff:ff:ff، والجواب {E(a2['info'])} يرجع مباشرة.", [1, 2]))
    R.append(("60 بايت مقابل 42", f"الطلب وصل للخادم بطول {a1['length']} بايت ومعه 18 بايت Padding. أما الرد فطوله {a2['length']} لأنه التُقط على الخادم قبل أن تضيف بطاقته الحشو.", [1, 2]))
    req = find(fr, icmp_type=8); rep = find(fr, icmp_type=0)
    R.append((f"{len(req)} طلبات، {len(rep)} ردود", "أرقام التسلسل " + "، ".join(str(s['icmp_seq']) for s in req) + f"، وكل رد بـ TTL {rep[0]['ttl']} و {req[0]['icmp_dlen']} بايت بيانات.", [req[0]['no'], rep[0]['no']]))
    R.append(("فرق Checksum ثابت", " · ".join(f"{q['icmp_ck']} ← {p['icmp_ck']}" for q, p in zip(req, rep)) + ". الفرق دائمًا 0x0800 لأن الحقل الوحيد الذي تغير هو Type من 8 إلى 0.", [req[0]['no'], rep[0]['no']]))
    tail = [f["s"] for f in fr[10:12]]
    R.append(("الخادم يسأل أيضًا", f"بعد الردود: {E(tail[0]['info'])}. كل طرف يحتفظ بجدول ARP خاص به.", [tail[0]['no'], tail[1]['no']]))
    return R

def findings_vlan():
    fr = frames("vlan"); fi = frames("intervlan"); R = []
    k = {}
    for f in fr:
        k[f["s"].get("proto")] = k.get(f["s"].get("proto"), 0) + 1
    R.append(("السويتشات تتكلم دائمًا", f"من {len(fr)} إطارًا على الـ Trunk: {k.get('STP',0)} إطار STP و {k.get('PVST+',0)} إطار PVST+ و {k.get('CDP',0)} CDP، قبل أي حركة من المستخدمين.", []))
    ping = find(fr, icmp_type=8)[0]; pong = find(fr, icmp_type=0)[0]
    R.append(("78 بايت بدل 74", f"طلب ping داخل VLAN {ping['vlan']} طوله {ping['length']} بايت: الأربعة الزائدة هي وسم 802.1Q.", [ping['no'], pong['no']]))
    rq = find(fi, icmp_type=8); rp = find(fi, icmp_type=0); a, b = rq[0], rq[1]
    R.append(("نفس الطلب مرتين على الـ Trunk", f"قبل الراوتر: VID {a['vlan']} · TTL {a['ttl']}<br>بعد الراوتر: VID {b['vlan']} · TTL {b['ttl']}<br>عنوانا IP ثابتان، والـ Checksum {a['icmp_ck']} لم يتغير.", [a['no'], b['no']], "intervlan"))
    R.append(("MAC يتغير في كل قفزة", f"{a['src_mac']} ← {a['dst_mac']} ثم {b['src_mac']} ← {b['dst_mac']}. الراوتر يكتب عنوانه مصدرًا في الإطار الجديد.", [a['no'], b['no']], "intervlan"))
    R.append(("الرد بنفس الطريق", f"VID {rp[0]['vlan']} · TTL {rp[0]['ttl']} ثم VID {rp[1]['vlan']} · TTL {rp[1]['ttl']}.", [rp[0]['no'], rp[1]['no']], "intervlan"))
    return R

FINDINGS = {"ftp": findings_ftp, "ftp-bulk": findings_bulk, "smtp-pop3": findings_smtp, "arp-icmp": findings_arp, "vlan-intervlan": findings_vlan}

# ------------------------------------------------------------------ sequence diagrams
def flow_html(cols, rows, cap=None, note=""):
    """cols: list of labels (index 0 drawn on the right). rows: dicts {a,b,label,sub,no,cls}."""
    n = len(cols)
    x = lambda i: (1 - (i + .5) / n) * 100
    head = "".join(f'<span style="left:{x(i):.2f}%">{E(c)}</span>' for i, c in enumerate(cols))
    guides = "".join(f'<i style="left:{x(i):.2f}%"></i>' for i in range(n))
    out = []
    for r in rows:
        a, b = x(r["a"]), x(r["b"])
        lo, hi = min(a, b), max(a, b)
        d = "l" if b < a else "r"
        attr = f' data-frame="{r["no"]}"' + (f' data-cap="{cap}"' if cap else "") if r.get("no") else ""
        out.append(f'<li class="fr {r.get("cls","")} d-{d}" style="--lo:{lo:.2f}%;--hi:{hi:.2f}%"{attr}>'
                   f'<span class="ln"></span><span class="lb" dir="auto">{E(r["label"])}</span>'
                   + (f'<span class="sb mono" dir="ltr">{E(r["sub"])}</span>' if r.get("sub") else "") + "</li>")
    return (f'<div class="flow"><div class="flow-h">{head}</div><div class="flow-g">{guides}</div><ol>{"".join(out)}</ol></div>'
            + (f'<p class="muted">{note}</p>' if note else ""))

def flow_tcp(capkey, hosts, ports=None, limit=None):
    fr = frames(capkey); rows = []
    retx = {r["no"] for r in tcp_checks(fr) if r["seq_status"] == "retx"}
    for f in fr:
        s = f["s"]
        if s.get("proto") != "TCP" or s["src"] not in hosts or s["dst"] not in hosts:
            continue
        if ports and s["sport"] not in ports and s["dport"] not in ports:
            continue
        fl = s["flags"]
        if s["plen"] == 0 and not any(k in fl for k in ("SYN", "FIN", "RST")):
            continue
        lab = first_line(s.get("payload_txt")) if s["plen"] else fl.replace(" ", "-")
        if s["plen"] and (s["sport"] in (49672, 49673) or s["dport"] in (49672, 49673)):
            lab = f"بيانات · {s['plen']} بايت"
        rows.append({"a": hosts.index(s["src"]), "b": hosts.index(s["dst"]), "label": lab + ("  ↺ إعادة إرسال" if s["no"] in retx else ""),
                     "sub": f"Seq {s['seq']} · Ack {s['ack']} · Len {s['plen']}", "no": s["no"], "cls": "rx" if s["no"] in retx else ("ctl" if not s["plen"] else "")})
    return rows[:limit] if limit else rows

def flow_block(g):
    if g["slug"] == "ftp":
        return flow_html(["العميل 189.120.0.57", "الخادم 189.120.0.58"], flow_tcp("ftp", ["189.120.0.57", "189.120.0.58"], limit=34), "ftp", "اضغط أي سهم لفتح الإطار في مستكشف الحزم.")
    if g["slug"] == "ftp-bulk":
        return flow_html(["العميل 189.120.0.57", "الخادم 189.120.0.58"], flow_tcp("ftp-bulk", ["189.120.0.57", "189.120.0.58"]), "ftp-bulk", "اضغط أي سهم لفتح الإطار.")
    if g["slug"] == "smtp-pop3":
        rows = flow_tcp("smtp", ["189.120.0.57", "189.120.0.58", "189.120.0.59"], ports=(587, 110))
        rows = [dict(r, b=r["b"], a=r["a"]) for r in rows]
        return flow_html(["المرسل .57", "خادم البريد .58", "المستقبل .59"], rows, "smtp", "اضغط أي سهم لفتح الإطار.")
    if g["slug"] == "arp-icmp":
        fr = frames("icmp-arp"); H = ["189.120.0.57", "189.120.0.58"]; rows = []
        for f in fr:
            s = f["s"]
            if s.get("proto") in ("ARP", "ICMP") and s["src"] in H and s["dst"] in H:
                lab = ("ARP · " + ("من يملك " + s["dst"] + "؟" if "Who" in s["info"] else "أنا " + s["src"])) if s["proto"] == "ARP" else ("Echo request" if s["icmp_type"] == 8 else "Echo reply") + f" · seq {s['icmp_seq']}"
                rows.append({"a": H.index(s["src"]), "b": H.index(s["dst"]), "label": lab, "sub": f"{s['length']} بايت" + (f" · TTL {s['ttl']}" if s.get('ttl') else ""), "no": s["no"], "cls": "arp" if s["proto"] == "ARP" else ""})
        return flow_html(["العميل 189.120.0.57", "الخادم 189.120.0.58"], rows, "icmp-arp", "اضغط أي سهم لفتح الإطار.")
    if g["slug"] == "vlan-intervlan":
        fi = frames("intervlan"); M = {}
        rq = find(fi, icmp_type=8); rp = find(fi, icmp_type=0)
        A, R_, B = rq[0]["src_mac"], rq[0]["dst_mac"], rq[1]["dst_mac"]
        idx = {A: 0, R_: 1, B: 2}
        rows = [{"a": idx[s["src_mac"]], "b": idx[s["dst_mac"]], "label": ("Echo request" if s["icmp_type"] == 8 else "Echo reply") + f" · VID {s['vlan']}", "sub": f"TTL {s['ttl']} · {s['src']} → {s['dst']}", "no": s["no"], "cls": "v10" if s["vlan"] == 10 else "v20"} for s in sorted(rq + rp, key=lambda s: s["no"])]
        return flow_html(["A · VLAN 10", "R · Router on a Stick", "B · VLAN 20"], rows, "intervlan", "نفس الطلب يمر على الـ Trunk مرتين. اضغط أي سهم لفتح الإطار.")
    if g["slug"] == "telnet":
        rows = []
        for no, d, c, ln in TELNET_REPORT:
            if d == "الاتجاهين":
                rows.append({"a": 0, "b": 1, "label": c, "sub": f"الرسائل {no}", "cls": "ctl"})
                continue
            a = 1 if d.startswith("الخادم") else 0
            rows.append({"a": a, "b": 1 - a, "label": c, "sub": f"الرسالة {no} · {ln} بايت" if ln not in ("—",) else f"الرسالة {no}"})
        return flow_html(["العميل 189.120.0.57", "الخادم 189.120.0.58"], rows)
    if g["slug"] == "tcp-piggybacking":
        p = PIGGY; rows = []; sa, sb = p["isn_a"] + 1, p["isn_b"] + 1
        for i in range(3):
            rows.append({"a": 1, "b": 0, "label": f"A{i+1} · {p['a'][i]} بايت + ACK", "sub": f"Seq {sa} · Ack {sb}"}); sa += p["a"][i]
            rows.append({"a": 0, "b": 1, "label": f"B{i+1} · {p['b'][i]} بايت + ACK", "sub": f"Seq {sb} · Ack {sa}"}); sb += p["b"][i]
        return flow_html(["B · منفذ 1070", "A · منفذ 110"], rows)
    if g["slug"] == "tcp-retransmission":
        rows = [{"a": 0, "b": 1, "label": "S4 · 12 بايت", "sub": "Seq 2046860036", "cls": "lost"},
                {"a": 0, "b": 1, "label": "S4 مرة ثانية بعد RTO", "sub": "Seq 2046860036 · Checksum 0xAAB3", "cls": "rx"},
                {"a": 1, "b": 0, "label": "S5 · 33 بايت", "sub": "Seq 3535721162 · Ack 2046860048"},
                {"a": 0, "b": 1, "label": "S6 · 6 بايت", "sub": "Seq 2046860048", "cls": "lost"},
                {"a": 0, "b": 1, "label": "S6 مرة ثانية بعد RTO", "sub": "Seq 2046860048 · Checksum 0x4033", "cls": "rx"}]
        return flow_html(["العميل · 1070", "الخادم · 110"], rows)
    return ""

# ------------------------------------------------------------------ html pieces
ICON = {
 "pc": '<rect x="-22" y="-16" width="44" height="28" rx="4"/><path d="M-28 16h56"/>',
 "server": '<rect x="-16" y="-22" width="32" height="44" rx="4"/><path d="M-9 -10h12M-9 0h12M-9 10h12"/><circle cx="9" cy="-10" r="1.8"/><circle cx="9" cy="0" r="1.8"/>',
 "switch": '<rect x="-30" y="-11" width="60" height="22" rx="5"/><path d="M-20 0h6M-8 0h6M4 0h6M16 0h6"/>',
 "router": '<ellipse cx="0" cy="-6" rx="24" ry="8"/><path d="M-24 -6v12a24 8 0 0 0 48 0v-12"/><path d="M-8 -6h16M0 -12v12"/>',
}

def topo_svg(t):
    if not t:
        return ""
    W, H = 820, 380 if len(t["nodes"]) > 3 else 240
    pos = {n[0]: (n[4] * W, n[5] * H) for n in t["nodes"]}
    out = [f'<svg class="topo" viewBox="0 0 {W} {H}" role="img" aria-label="مخطط الشبكة">']
    for i, (a, b, lab) in enumerate(t["links"]):
        (x1, y1), (x2, y2) = pos[a], pos[b]
        out.append(f'<line class="lk" x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}"/><circle class="pk" r="4"><animateMotion dur="{2.4 + i * .4}s" repeatCount="indefinite" path="M{x1:.0f},{y1:.0f} L{x2:.0f},{y2:.0f}"/></circle>')
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        out.append(f'<text class="lkl" x="{mx:.0f}" y="{my - 12:.0f}" text-anchor="middle">{E(lab)}</text>')
    for nid, name, sub, ip, x, y, kind in t["nodes"]:
        X, Y = pos[nid]
        out.append(f'<g class="nd" transform="translate({X:.0f},{Y:.0f})"><circle class="halo" r="38"/><g class="ic">{ICON[kind]}</g>'
                   f'<text class="n1" y="54" text-anchor="middle">{E(name)}</text><text class="n2" y="72" text-anchor="middle">{E(sub)}</text>'
                   + (f'<text class="n3" y="90" text-anchor="middle">{E(ip)}</text>' if ip else "") + '</g>')
    out.append("</svg>")
    return "".join(out)

def code(lang, txt):
    return (f'<div class="code"><div class="code-h"><span>{E(lang)}</span><button type="button" class="copy">نسخ</button></div>'
            f'<pre dir="ltr"><code>{E(txt)}</code></pre></div>')

def link(k):
    return L[k] if isinstance(k, str) else k

def sidebar(active):
    out = ['<nav class="side" aria-label="المشاريع">']
    for course, title in (("COS 370", "بروتوكولات الشبكات"), ("COS 372", "محاكاة الشبكات")):
        out.append(f'<div class="side-g"><p class="side-h"><span class="mono">{course}</span> {title}</p><ul>')
        for g in sorted([g for g in GUIDES if g["course"] == course], key=lambda g: g["order"]):
            cur = ' aria-current="page"' if g["slug"] == active else ""
            out.append(f'<li><a href="../{g["slug"]}/"{cur}>{E(g["title"])}</a></li>')
        out.append("</ul></div>")
    out.append("</nav>")
    return "".join(out)

def head(title, desc, depth):
    pre = "../" * depth
    return f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{E(title)}</title>
<meta name="description" content="{E(desc)}">
<meta property="og:title" content="{E(title)}">
<meta property="og:description" content="{E(desc)}">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%23111433'/%3E%3Cpath d='M9 22l7-12 7 12' stroke='%237C83FF' stroke-width='3' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap">
<link rel="stylesheet" href="{pre}assets/site.css">
<script>try{{var t=localStorage.getItem('fnl-theme');if(t)document.documentElement.dataset.theme=t}}catch(e){{}}</script>
</head>
<body>
<a class="skip" href="#main">تخطَّ إلى المحتوى</a>
<header class="top"><div class="top-in">
<a class="brand" href="{pre}"><span class="logo" aria-hidden="true"></span><span>Fahad Net Lab</span></a>
<nav class="top-nav" aria-label="الرئيسية"><a href="{pre}#story">الشبكة</a><a href="{pre}#projects">المشاريع</a><a href="{WP}" rel="noopener">المدونة</a></nav>
<button class="theme" type="button" aria-label="تبديل المظهر"><span aria-hidden="true"></span></button>
<button class="menu" type="button" aria-label="قائمة المشاريع" aria-expanded="false"><span aria-hidden="true"></span></button>
</div></header>"""

FOOT = """<footer class="foot"><div class="foot-in"><span>© 2026 فهد عواد · Fahad Net Lab</span><span>جامعة الملك سعود · COS 370 · COS 372</span></div></footer>
<script src="{pre}assets/site.js" defer></script>
</body></html>"""

def explorer_block(capkey, label):
    fr = frames(capkey)
    data = [{"s": f["s"], "l": f["layers"], "h": f["hex"]} for f in fr]
    j = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return (f'<div class="xp" data-cap="{capkey}"><div class="xp-h"><b>{E(label)}</b>'
            f'<a href="../../captures/{capkey}.pcapng" download>تحميل {capkey}.pcapng</a>'
            f'<label class="xp-f"><span class="sr">بحث في الإطارات</span><input type="search" id="flt-{capkey}" placeholder="ابحث: PASV، icmp، vlan…" dir="auto"></label></div>'
            f'<div class="xp-b"><div class="xp-list" role="listbox" aria-label="الإطارات"></div><div class="xp-d"><div class="xp-tree"></div><div class="xp-hex" dir="ltr"></div></div></div>'
            f'<script type="application/json" class="xp-data">{j}</script></div>')

def piggy_block():
    p = PIGGY; rows = []; sa, sb = p["isn_a"] + 1, p["isn_b"] + 1
    for i in range(3):
        rows.append((f"A{i+1}", sa, sb, p["a"][i])); sa += p["a"][i]
        rows.append((f"B{i+1}", sb, sa, p["b"][i])); sb += p["b"][i]
    body = "".join(f'<tr><td class="mono">{k}</td><td class="mono">{s}</td><td class="mono">{a}</td><td class="mono">{n}</td><td class="mono">{p["report_win"][k]}</td><td class="mono">{p["report_chk"][k]}</td></tr>' for k, s, a, n in rows)
    hx = p["report_hex_A1"].split()
    flds = [("Src Port", 0, 2), ("Dst Port", 2, 2), ("Seq", 4, 4), ("Ack", 8, 4), ("HLen · Flags", 12, 2), ("Window", 14, 2), ("Checksum", 16, 2), ("Urgent", 18, 2)]
    dec = [str(int("".join(hx[0:2]), 16)), str(int("".join(hx[2:4]), 16)), str(int("".join(hx[4:8]), 16)), str(int("".join(hx[8:12]), 16)), "20B · ACK PSH", str(int("".join(hx[14:16]), 16)), "0x" + "".join(hx[16:18]), str(int("".join(hx[18:20]), 16))]
    cells = "".join(f'<div class="hc"><span class="mono h">{" ".join(hx[o:o+n])}</span><span class="f">{f}</span><span class="mono v">{v}</span></div>' for (f, o, n), v in zip(flds, dec))
    return (f'<div class="tbl"><table><thead><tr><th>المقطع</th><th>Seq</th><th>Ack</th><th>Len</th><th>Window</th><th>Checksum</th></tr></thead><tbody>{body}</tbody></table></div>'
            f'<h3 class="sub-h">هيدر A1 بالـ Hex</h3><div class="hexcells" dir="ltr">{cells}</div>')

def eth_block():
    body = "".join(f"<tr><td class='mono'>{a}</td><td>{E(b)}</td><td class='mono'>{c}</td><td>{E(e)}</td></tr>" for a, b, c, d, e in ETH_TABLE)
    return f'<div class="tbl"><table><thead><tr><th>السنة</th><th>التقنية والمعيار</th><th>السرعة</th><th>أقصى طول</th></tr></thead><tbody>{body}</tbody></table></div>'

# ------------------------------------------------------------------ guide page
def guide_page(g):
    toc, sec = [], []
    def H(id_, title, body, cls=""):
        toc.append((id_, title)); sec.append(f'<section id="{id_}" class="sec {cls}"><h2>{E(title)}</h2>{body}</section>')

    if g["tools"]:
        rows = "".join(f'<li class="tool"><a href="{E(link(k)[1])}" rel="noopener"><b>{E(link(k)[0])}</b><span>{E(role)}</span></a></li>' for k, role in g["tools"])
        H("software", "البرامج", f'<ul class="tools">{rows}</ul>' + (f'<p class="note">{g["tool_note"]}</p>' if g["tool_note"] else ""))
    if g["install"]:
        items = "".join(f'<li><h3>{E(t)}</h3><p>{b}</p>{code(*c) if c else ""}</li>' for t, b, c in g["install"])
        H("setup", "التجهيز", f'<ol class="steps">{items}</ol>')
    if g["steps"]:
        items = []
        for t, b, c, ex in g["steps"]:
            exl = "".join(f'<li><code dir="ltr">{E(k)}</code><span>{E(v)}</span></li>' for k, v in ex)
            items.append(f'<li><h3>{E(t)}</h3>' + (f"<p>{b}</p>" if b else "") + (code(*c) if c else "") + (f'<ul class="explain">{exl}</ul>' if exl else "") + "</li>")
        H("steps", "التنفيذ", f'<ol class="steps">{"".join(items)}</ol>')
    if g["filters"]:
        fl = "".join(f'<li><code dir="ltr">{E(a)}</code><span>{E(b)}</span></li>' for a, b in g["filters"])
        sec[-1] = sec[-1].replace("</section>", f'<h3 class="sub-h">فلاتر مفيدة في Wireshark</h3><ul class="explain">{fl}</ul></section>')
    fb = flow_block(g)
    if fb:
        H("flow", "مسار الجلسة", fb, "wide")
    if g["slug"] == "tcp-piggybacking":
        H("calc", "الأرقام", piggy_block())
    if g["slug"] == "ethernet-history":
        H("table", "المراحل", eth_block())
    if g["cap"]:
        caps = [(g["cap"], "داخل الحزم")] + ([(g["cap2"], "InterVLAN")] if g.get("cap2") else [])
        H("explorer", "داخل الحزم", '<p class="muted">اختر إطارًا، ومرّر المؤشر على أي حقل ليظهر مكانه في البايتات.</p>' + "".join(explorer_block(c, l) for c, l in caps), "wide")
    if g["slug"] in FINDINGS:
        items = []
        for f in FINDINGS[g["slug"]]():
            t, b, refs = f[0], f[1], f[2]; capk = f[3] if len(f) > 3 else g["cap"]
            items.append(f'<li><h3>{E(t)}</h3><p>{b}</p>' + (f'<p class="refs">{" ".join(fref(n, capk) for n in refs)}</p>' if refs else "") + "</li>")
        H("results", "ماذا كشف الالتقاط", f'<ul class="findings">{"".join(items)}</ul>')
    if g["errors"]:
        er = "".join(f'<details class="err"><summary>{E(a)}</summary><p>{b}</p><p><b>الحل:</b> {c}</p></details>' for a, b, c in g["errors"])
        H("errors", "مشاكل وحلول", er)
    rf = "".join(f'<li><a href="{E(u)}" rel="noopener">{E(t)}</a></li>' for t, u in g["refs"])
    li = (f'<details class="li"><summary>ملخص المشروع لـ LinkedIn</summary><div class="li-g">'
          f'<div class="li-c"><div class="li-h"><b>العربية</b><button type="button" class="copy" data-copy="li-ar-{g["slug"]}">نسخ</button></div><p id="li-ar-{g["slug"]}">{E(g["li_ar"])}</p></div>'
          f'<div class="li-c" dir="ltr" lang="en"><div class="li-h"><b>English</b><button type="button" class="copy" data-copy="li-en-{g["slug"]}">Copy</button></div><p id="li-en-{g["slug"]}">{E(g["li_en"])}</p></div></div></details>')
    H("refs", "المراجع", f'<ul class="refs-l">{rf}</ul>{li}')

    ordered = sorted(GUIDES, key=lambda x: x["order"]); i = ordered.index(g)
    prv = ordered[i - 1] if i > 0 else None; nxt = ordered[i + 1] if i < len(ordered) - 1 else None
    pn = ('<nav class="pn" aria-label="التنقل بين المشاريع">' + (f'<a href="../{prv["slug"]}/"><span>السابق</span><b>{E(prv["title"])}</b></a>' if prv else "<span></span>")
          + (f'<a class="nx" href="../{nxt["slug"]}/"><span>التالي</span><b>{E(nxt["title"])}</b></a>' if nxt else "") + "</nav>")
    learn = "".join(f"<li>{E(x)}</li>" for x in g["learn"])
    hero = (f'<header class="ghero"><div class="ghero-in"><div class="ghero-t"><p class="crumb mono">{g["course"]} · {g["order"]:02d}</p><h1>{E(g["title"])}</h1>'
            f'<p class="lead">{E(g["summary"])}</p><ul class="learn">{learn}</ul></div>'
            + (f'<div class="ghero-v">{topo_svg(g["topo"])}' + (f'<p class="cap">{E(g["ip_note"])}</p>' if g["ip_note"] else "") + '</div>' if g["topo"] else "") + '</div></header>')
    tocl = "".join(f'<li><a href="#{a}">{E(b)}</a></li>' for a, b in toc)
    page = (head(f'{g["title"]} · Fahad Net Lab', g["summary"], 2) + hero
            + f'<div class="docs">{sidebar(g["slug"])}<main id="main" class="doc">{"".join(sec)}{pn}</main><aside class="toc" aria-label="في هذه الصفحة"><p>في هذه الصفحة</p><ul>{tocl}</ul></aside></div>'
            + FOOT.replace("{pre}", "../../"))
    d = os.path.join(ROOT, "guides", g["slug"]); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "index.html"), "w").write(page)

if __name__ == "__main__":
    for g in GUIDES:
        guide_page(g); print("built", g["slug"])
    story = {}
    fa = frames("icmp-arp"); ff = frames("ftp"); fi = frames("intervlan")
    story["arp"] = [S(fa, 1)["info"], S(fa, 2)["info"]]
    story["ping"] = {"req": len(find(fa, icmp_type=8)), "rep": len(find(fa, icmp_type=0)), "ttl": find(fa, icmp_type=0)[0]["ttl"]}
    syn = find(ff, flags="SYN", dport=21)[0]; sa = find(ff, flags="SYN ACK", sport=21)[0]; ak = S(ff, 4)
    story["hs"] = [(syn["seq"], 0), (sa["seq"], sa["ack"]), (ak["seq"], ak["ack"])]
    q = find(fi, icmp_type=8)
    story["iv"] = [(q[0]["vlan"], q[0]["ttl"]), (q[1]["vlan"], q[1]["ttl"])]
    story["macs"] = {"A": S(fa, 1)["src_mac"], "B": S(fa, 2)["src_mac"]}
    story["ticker"] = [{"no": f["s"]["no"], "t": round(f["s"]["rt"], 3), "src": f["s"]["src"], "dst": f["s"]["dst"],
                        "p": "FTP" if f["s"].get("plen") else "TCP", "i": first_line(f["s"].get("payload_txt"), 40) or f["s"]["flags"]}
                       for f in ff if f["s"].get("proto") == "TCP"][:16]
    json.dump(story, open(os.path.join(ROOT, "tools", "story.json"), "w"), ensure_ascii=False, indent=1)
    print("story ok")
