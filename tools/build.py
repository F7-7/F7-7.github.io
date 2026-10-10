# -*- coding: utf-8 -*-
"""Build the static site: guides/<slug>/index.html from content.py + captures, and index.html.
Run:  python3 -I tools/build.py   (from the repo root)"""
import base64, html, json, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from decode import load, tcp_checks
from content import GUIDES, L, ETH_TABLE, PIGGY, TELNET_REPORT

CAP = os.path.join(ROOT, "captures")
E = html.escape
WP = "https://fahadnetlab.wordpress.com"
STATUS = {"capture": ("data", "من ملف التقاط حقيقي", "كل رقم في النتائج ومستكشف الحزم مقروء من ملف الالتقاط مباشرة."),
          "theory": ("theory", "سيناريو نظري", "القيم معطاة في التقرير، والحسابات تُعاد آليًا عند بناء الصفحة."),
          "report": ("report", "من التقرير", "القيم منقولة من التقرير كما هي."),
          "pending": ("pending", "بانتظار ملف الالتقاط", "القيم منقولة من التقرير ولم يُتحقق منها، لأن ملف الالتقاط غير متوفر.")}

frames_cache = {}
def frames(key):
    if key not in frames_cache:
        frames_cache[key] = load(os.path.join(CAP, key + ".pcapng"))
    return frames_cache[key]

def S(fr, n):
    return fr[n - 1]["s"]

def find(fr, **kw):
    out = []
    for f in fr:
        s = f["s"]
        if all((s.get(k) == v) if not callable(v) else v(s.get(k)) for k, v in kw.items()):
            out.append(s)
    return out

def fref(n, cap=None):
    c = f' data-cap="{cap}"' if cap else ""
    return f'<button class="fref" data-frame="{n}"{c} type="button">#{n}</button>'

# ------------------------------------------------------------------ findings per capture
def findings_ftp():
    fr = frames("ftp"); R = []
    syn = find(fr, flags="SYN", dport=21)[0]
    sa = find(fr, flags="SYN ACK", sport=21)[0]
    R.append(("المصافحة الثلاثية", f"SYN بـ Seq={syn['seq']}، والرد SYN-ACK بـ Seq={sa['seq']} و Ack={sa['ack']} = {syn['seq']} + 1.", [syn['no'], sa['no']]))
    for s in fr:
        s = s["s"]
        t = s.get("payload_txt", "")
        if t.startswith("227"):
            m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", t)
            p1, p2 = int(m.group(5)), int(m.group(6)); port = p1 * 256 + p2
            syn2 = find(fr, flags="SYN", dport=port)
            R.append(("منفذ البيانات من رد 227", f"<code>{E(t.strip())}</code> → {p1} × 256 + {p2} = <b>{port}</b>. " + (f"وفعلًا فتح العميل اتصالًا جديدًا على {port} في الإطار التالي." if syn2 else "لم يظهر اتصال على هذا المنفذ."), [s['no']] + ([syn2[0]['no']] if syn2 else [])))
    lst = [f["s"] for f in fr if f["s"].get("sport") == 49672 and f["s"].get("plen", 0) > 0]
    if lst:
        R.append(("محتوى LIST", f"قناة البيانات حملت {lst[0]['plen']} بايت: <code>{E(lst[0]['payload_txt'].strip())}</code>", [lst[0]['no']]))
    retr = find(fr, payload_txt=lambda v: bool(v) and v.startswith("RETR"))
    size = find(fr, payload_txt=lambda v: bool(v) and v.startswith("213"))
    if retr:
        R.append(("طلب تحميل لم يرد في التقرير", f"في آخر الجلسة طلب العميل <code>{E(retr[0]['payload_txt'].strip())}</code>، وكان رد SIZE <code>{E(size[0]['payload_txt'].strip())}</code>: الملف فارغ، لذلك أُغلق اتصال البيانات الثاني دون بيانات.", [size[0]['no'], retr[0]['no']]))
    pw = find(fr, payload_txt=lambda v: bool(v) and v.startswith("PASS"))[0]
    R.append(("كلمة المرور على الشبكة", f"أمر PASS ظاهر نصًا: <code>{E(pw['payload_txt'].strip())}</code>. في الدخول المجهول تكون كلمة المرور بريدًا شكليًا، لكن الدخول بحساب حقيقي يكشف كلمة المرور بنفس الطريقة.", [pw['no']]))
    return R

def findings_bulk():
    fr = frames("ftp-bulk"); R = []
    size = find(fr, payload_txt=lambda v: bool(v) and v.startswith("213"))[0]
    retr = find(fr, payload_txt=lambda v: bool(v) and v.startswith("RETR"))[0]
    R.append(("الحجم قبل التحميل", f"<code>{E(retr['payload_txt'].strip())}</code> سبقه SIZE، والرد <code>{E(size['payload_txt'].strip())}</code>.", [size['no'], retr['no']]))
    big = max((f["s"] for f in fr if f["s"].get("proto") == "TCP"), key=lambda s: s["plen"])
    ack = find(fr, ack=big["seq"] + big["plen"], dport=big["sport"])[0]
    R.append(("الملف في إطار واحد", f"الإطار حجمه {big['length']} بايت ويحمل {big['plen']} بايت بيانات من Seq={big['seq']}. رد العميل بـ Ack={ack['ack']} = {big['seq']} + {big['plen']}.", [big['no'], ack['no']]))
    if big.get("tso"):
        R.append(("حقل IP Total Length = 0", "هذه علامة TCP Segmentation Offload: نظام التشغيل يسلّم البطاقة كتلة كبيرة، والبطاقة تقسمها لمقاطع لا تتجاوز MSS وتملأ الطول. Wireshark يلتقط قبل التقسيم، فيرى الكتلة كاملة والطول صفرًا.", [big['no']]))
    rst = find(fr, flags=lambda v: bool(v) and "RST" in v)
    if rst:
        R.append(("الإغلاق", f"الخادم أغلق قناة البيانات بـ FIN، والعميل أنهاها بـ {rst[-1]['flags']}.", [rst[-1]['no']]))
    return R

def findings_smtp():
    fr = frames("smtp"); R = []
    for s in find(fr, payload_txt=lambda v: bool(v) and v.startswith("334")):
        enc = s["payload_txt"][4:].strip()
        R.append(("طلب المصادقة", f"<code>{E(enc)}</code> بعد فك Base64 = <code>{E(base64.b64decode(enc).decode())}</code>", [s['no']]))
    u = find(fr, payload_txt=lambda v: bool(v) and v.strip() == "ZmFoYWRAbXltYWlsLmNvbQ==")[0]
    R.append(("اسم المستخدم مكشوف", f"العميل أرسل <code>{E(u['payload_txt'].strip())}</code> = <code>{base64.b64decode(u['payload_txt'].strip()).decode()}</code>. وكلمة المرور أُرسلت بنفس الطريقة في الإطار التالي (كلمة تجريبية للمختبر).", [u['no']]))
    mf = find(fr, payload_txt=lambda v: bool(v) and v.startswith("MAIL FROM"))[0]
    data = [f["s"] for f in fr if f["s"].get("dport") == 587 and f["s"].get("plen", 0) > 100][0]
    R.append(("حجم الرسالة المرسلة", f"<code>{E(mf['payload_txt'].strip())}</code>، والرسالة نفسها في إطار واحد طوله {data['plen']} بايت.", [mf['no'], data['no']]))
    rows = tcp_checks(fr)
    for r in rows:
        if r["seq_status"] == "retx":
            prev = [x for x in rows if x["no"] < r["no"] and x["dir"] == r["dir"] and x["seq"] == r["seq"] and x["len"] > 0]
            p = prev[-1] if prev else None
            R.append(("إعادة إرسال TCP", f"الإطار #{r['no']} يحمل نفس Seq={r['seq']} " + (f"الذي ظهر في #{p['no']} (الطول {p['len']} ثم {r['len']})." if p else "."), ([p['no']] if p else []) + [r['no']]))
    rt = find(fr, payload_txt=lambda v: bool(v) and v.startswith("+OK 529"))[0]
    R.append(("حجم الرسالة المستلمة", "رد RETR يبدأ بـ <code>+OK 529 octets</code>. الفرق عن 403 بايت هو ترويسات Return-Path و Received التي أضافها الخادم.", [rt['no']]))
    return R

def findings_arp():
    fr = frames("icmp-arp"); R = []
    a1, a2 = S(fr, 1), S(fr, 2)
    R.append(("طلب ARP بالبث", f"{E(a1['info'])}. وجهته {a1['dst_mac']}، وطول الإطار {a1['length']} بايت.", [1]))
    R.append(("رد ARP مباشر", f"{E(a2['info'])}. طول الإطار {a2['length']} بايت بلا Padding. الطلب خرج من جهاز الالتقاط مع الحشو، والرد وصل له بدونه في هذا الالتقاط.", [2]))
    req = find(fr, icmp_type=8); rep = find(fr, icmp_type=0)
    R.append((f"{len(req)} طلبات و {len(rep)} ردود", "أرقام التسلسل " + "، ".join(str(s['icmp_seq']) for s in req) + f". كل الردود بـ TTL={rep[0]['ttl']}، وبيانات كل رسالة {req[0]['icmp_dlen']} بايت.", [s['no'] for s in req[:1] + rep[:1]]))
    ck = "، ".join(f"{q['icmp_ck']}/{p['icmp_ck']}" for q, p in zip(req, rep))
    R.append(("Checksum الطلب والرد", f"{ck}. الفرق الثابت 0x0800 سببه تغير حقل Type من 8 إلى 0 فقط.", [req[0]['no'], rep[0]['no']]))
    tail = [f["s"] for f in fr[10:12]]
    R.append(("ARP في الاتجاه المعاكس", f"بعد الردود سأل الخادم عن عنوان العميل ({E(tail[0]['info'])})، وهذا لم يرد في التقرير.", [tail[0]['no'], tail[1]['no']]))
    return R

def findings_vlan():
    fr = frames("vlan"); fi = frames("intervlan"); R = []
    kinds = {}
    for f in fr:
        k = f["s"].get("proto")
        kinds[k] = kinds.get(k, 0) + 1
    tagged = [f["s"] for f in fr if f["s"].get("vlan") is not None]
    R.append(("إطارات التحكم", f"من أصل {len(fr)} إطارًا: STP={kinds.get('STP',0)}، PVST+={kinds.get('PVST+',0)}، CDP={kinds.get('CDP',0)}. السويتشات ترسلها كل ثانيتين تقريبًا حتى بدون حركة مستخدمين.", []))
    ping = find(fr, icmp_type=8)[0]; pong = find(fr, icmp_type=0)[0]
    R.append(("ping داخل VLAN 10", f"الطلب من {ping['src']} إلى {ping['dst']} بوسم VID={ping['vlan']} و seq={ping['icmp_seq']}، وطول الإطار {ping['length']} بايت (74 + 4 بايت الوسم). سبقه طلب ARP داخل نفس الـ VLAN.", [ping['no'], pong['no']]))
    rq = find(fi, icmp_type=8); rp = find(fi, icmp_type=0)
    a, b = rq[0], rq[1]
    R.append(("نفس الطلب يعبر الـ Trunk مرتين", f"#{a['no']}: VID={a['vlan']} · TTL={a['ttl']} · من {a['src_mac']} إلى {a['dst_mac']}<br>#{b['no']}: VID={b['vlan']} · TTL={b['ttl']} · من {b['src_mac']} إلى {b['dst_mac']}", [a['no'], b['no']], "intervlan"))
    R.append(("ما تغير وما بقي", f"تغير الوسم من {a['vlan']} إلى {b['vlan']}، ونقص TTL بواحد، وتغيرت عناوين MAC. بقي عنوانا IP ({a['src']} → {a['dst']}) و Checksum الـ ICMP ({a['icmp_ck']}) كما هما.", [a['no'], b['no']], "intervlan"))
    R.append(("الرد بنفس الطريقة", f"#{rp[0]['no']}: VID={rp[0]['vlan']} · TTL={rp[0]['ttl']}، ثم #{rp[1]['no']}: VID={rp[1]['vlan']} · TTL={rp[1]['ttl']}.", [rp[0]['no'], rp[1]['no']], "intervlan"))
    return R

FINDINGS = {"ftp": findings_ftp, "ftp-bulk": findings_bulk, "smtp-pop3": findings_smtp, "arp-icmp": findings_arp, "vlan-intervlan": findings_vlan}

# ------------------------------------------------------------------ html helpers
ICON = {
 "pc": '<rect x="-22" y="-16" width="44" height="28" rx="4"/><path d="M-28 16h56"/>',
 "server": '<rect x="-16" y="-22" width="32" height="44" rx="4"/><path d="M-9 -10h12M-9 0h12M-9 10h12"/><circle cx="9" cy="-10" r="1.8"/><circle cx="9" cy="0" r="1.8"/>',
 "switch": '<rect x="-30" y="-11" width="60" height="22" rx="5"/><path d="M-20 0h6M-8 0h6M4 0h6M16 0h6"/>',
 "router": '<ellipse cx="0" cy="-6" rx="24" ry="8"/><path d="M-24 -6v12a24 8 0 0 0 48 0v-12"/><path d="M-8 -6h16M0 -12v12"/>',
}

def topo_svg(t):
    if not t:
        return ""
    W, H = 820, 360 if len(t["nodes"]) > 3 else 250
    pos = {n[0]: (n[4] * W, n[5] * H) for n in t["nodes"]}
    out = [f'<svg class="topo" viewBox="0 0 {W} {H}" role="img" aria-label="مخطط الشبكة">']
    for a, b, lab in t["links"]:
        (x1, y1), (x2, y2) = pos[a], pos[b]
        out.append(f'<line class="lk" x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}"/>')
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        out.append(f'<text class="lkl" x="{mx:.0f}" y="{my - 10:.0f}" text-anchor="middle">{E(lab)}</text>')
    for nid, name, sub, ip, x, y, kind in t["nodes"]:
        X, Y = pos[nid]
        out.append(f'<g class="nd" transform="translate({X:.0f},{Y:.0f})"><circle class="halo" r="40"/><g class="ic">{ICON[kind]}</g>'
                   f'<text class="n1" y="50" text-anchor="middle">{E(name)}</text><text class="n2" y="68" text-anchor="middle">{E(sub)}</text>'
                   + (f'<text class="n3" y="86" text-anchor="middle">{E(ip)}</text>' if ip else "") + '</g>')
    out.append("</svg>")
    return "".join(out)

def code(lang, txt):
    return (f'<div class="code"><div class="code-h"><span>{E(lang)}</span><button type="button" class="copy">نسخ</button></div>'
            f'<pre dir="ltr"><code>{E(txt)}</code></pre></div>')

def link(key_or_pair):
    name, url = L[key_or_pair] if isinstance(key_or_pair, str) else key_or_pair
    return name, url

def sidebar(active):
    out = ['<nav class="side" aria-label="الأدلة">']
    for course, title in (("COS 370", "بروتوكولات الشبكات"), ("COS 372", "محاكاة الشبكات")):
        out.append(f'<div class="side-g"><p class="side-h"><span class="mono">{course}</span> {title}</p><ul>')
        for g in sorted([g for g in GUIDES if g["course"] == course], key=lambda g: g["order"]):
            cur = ' aria-current="page"' if g["slug"] == active else ""
            out.append(f'<li><a href="../{g["slug"]}/"{cur}><span class="dot st-{STATUS[g["status"]][0]}"></span>{E(g["title"])}</a></li>')
        out.append("</ul></div>")
    out.append('<div class="side-g"><p class="side-h">المنصة</p><ul><li><a href="../../#story">الشبكة خطوة بخطوة</a></li><li><a href="../../#method">منهجية البيانات</a></li><li><a href="' + WP + '" rel="noopener">المدونة على WordPress</a></li></ul></div></nav>')
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
<nav class="top-nav" aria-label="الرئيسية"><a href="{pre}#story">الشبكة</a><a href="{pre}guides/ftp/">الأدلة</a><a href="{pre}#method">المنهجية</a><a href="{WP}" rel="noopener">المدونة</a></nav>
<button class="theme" type="button" aria-label="تبديل المظهر"><span aria-hidden="true"></span></button>
<button class="menu" type="button" aria-label="قائمة الأدلة" aria-expanded="false"><span aria-hidden="true"></span></button>
</div></header>"""

FOOT = """<footer class="foot"><div class="foot-in"><span>© 2026 فهد عواد · Fahad Net Lab</span><span>جامعة الملك سعود · COS 370 · COS 372</span></div></footer>
<script src="{pre}assets/site.js" defer></script>
</body></html>"""

def explorer_block(capkey, label):
    fr = frames(capkey)
    data = [{"s": f["s"], "l": f["layers"], "h": f["hex"]} for f in fr]
    j = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return (f'<div class="xp" data-cap="{capkey}"><div class="xp-h"><b>{E(label)}</b><span class="mono">{capkey}.pcapng · {len(fr)} إطار</span>'
            f'<a href="../../captures/{capkey}.pcapng" download>تحميل ملف الالتقاط</a><label class="xp-f"><span class="sr">تصفية</span><input type="search" id="flt-{capkey}" placeholder="تصفية: tcp، 21، PASV، vlan…" dir="ltr"></label></div>'
            f'<div class="xp-b"><div class="xp-list" role="listbox" aria-label="الإطارات"></div><div class="xp-d"><div class="xp-tree"></div><div class="xp-hex" dir="ltr"></div></div></div>'
            f'<script type="application/json" class="xp-data">{j}</script></div>')

def checks_block(capkey):
    rows = tcp_checks(frames(capkey))
    if not rows:
        return ""
    ok = sum(1 for r in rows if r["seq_status"] == "ok")
    ex = sum(1 for r in rows if r["ack_ok"] == "exact")
    acks = sum(1 for r in rows if r["ack_ok"] is not None)
    retx = [r for r in rows if r["seq_status"] == "retx"]
    part = [r for r in rows if r["ack_ok"] == "partial"]
    body = "".join(
        f'<tr class="ck-{r["seq_status"]}"><td>{fref(r["no"], capkey)}</td><td dir="ltr" class="mono">{E(r["dir"])}</td><td class="mono">{E(r["flags"])}</td>'
        f'<td class="mono">{r["seq"]}</td><td class="mono">{r["len"]}</td><td class="mono">{r["next"]}</td><td class="mono">{r["ack"]}</td>'
        f'<td>{ {"exact":"✓ مطابق","partial":"تأكيد جزئي","beyond":"أكبر من المتوقع",None:"—"}[r["ack_ok"]] }</td><td>{E(r["note"])}</td></tr>' for r in rows)
    return (f'<div class="kpis"><div><b class="mono">{ok}/{len(rows)}</b><span>Seq في مكانه المتوقع</span></div>'
            f'<div><b class="mono">{ex}/{acks}</b><span>Ack يطابق آخر بايت متوقع</span></div>'
            f'<div><b class="mono">{len(retx)}</b><span>إعادة إرسال</span></div><div><b class="mono">{len(part)}</b><span>تأكيد جزئي (طبيعي)</span></div></div>'
            f'<details class="ck"><summary>عرض الجدول الكامل ({len(rows)} مقطع TCP)</summary><div class="tbl"><table><thead><tr><th>#</th><th>الاتجاه</th><th>Flags</th><th>Seq</th><th>Len</th><th>Seq التالي</th><th>Ack</th><th>Ack</th><th>ملاحظة</th></tr></thead><tbody>{body}</tbody></table></div></details>'
            '<p class="muted">طريقة الحساب: لكل اتجاه، Seq التالي = Seq + Len (+1 مع SYN أو FIN). ثم نقارن Ack كل مقطع بـ Seq التالي المتوقع من الطرف الآخر. «تأكيد جزئي» يعني أن المستقبل أكد جزءًا من البيانات فقط، وهذا يحدث مع Delayed ACK.</p>')

def piggy_block():
    p = PIGGY; rows = []
    sa, sb = p["isn_a"] + 1, p["isn_b"] + 1
    for i in range(3):
        rows.append((f"A{i+1}", "A → B", sa, sb, p["a"][i]))
        sa += p["a"][i]
        rows.append((f"B{i+1}", "B → A", sb, sa, p["b"][i]))
        sb += p["b"][i]
    body = "".join(f'<tr><td class="mono">{k}</td><td>{d}</td><td class="mono">{s}</td><td class="mono">{a}</td><td class="mono">{n}</td><td class="mono">{s + n}</td><td class="mono">{p["report_win"][k]}</td><td class="mono">{p["report_chk"][k]}</td></tr>' for k, d, s, a, n in rows)
    hx = p["report_hex_A1"].split()
    flds = [("Src Port", 0, 2), ("Dst Port", 2, 2), ("Seq", 4, 4), ("Ack", 8, 4), ("HLen · Flags", 12, 2), ("Window", 14, 2), ("Checksum", 16, 2), ("Urgent", 18, 2)]
    dec = [str(int("".join(hx[0:2]), 16)), str(int("".join(hx[2:4]), 16)), str(int("".join(hx[4:8]), 16)), str(int("".join(hx[8:12]), 16)), "0x5018 → 20B · ACK PSH", str(int("".join(hx[14:16]), 16)), "0x" + "".join(hx[16:18]), str(int("".join(hx[18:20]), 16))]
    cells = "".join(f'<div class="hc"><span class="mono h">{" ".join(hx[o:o+n])}</span><span class="f">{f}</span><span class="mono v">{v}</span></div>' for (f, o, n), v in zip(flds, dec))
    return (f'<div class="tbl"><table><thead><tr><th>المقطع</th><th>الاتجاه</th><th>Seq</th><th>Ack</th><th>Len</th><th>Seq التالي</th><th>Window*</th><th>Checksum*</th></tr></thead><tbody>{body}</tbody></table></div>'
            '<p class="muted">Seq و Ack محسوبة آليًا من ISN والأطوال. القيم المعلّمة بـ * منقولة من التقرير ولا يمكن حسابها من السيناريو وحده.</p>'
            f'<h3>هيدر المقطع A1 بالـ Hex (من التقرير، مفكوكًا آليًا)</h3><div class="hexcells" dir="ltr">{cells}</div>')

def eth_block():
    body = "".join(f"<tr><td class='mono'>{a}</td><td>{E(b)}</td><td class='mono'>{c}</td><td class='mono'>{d}</td><td>{E(e)}</td></tr>" for a, b, c, d, e in ETH_TABLE)
    return f'<div class="tbl"><table><thead><tr><th>السنة</th><th>التقنية والمعيار</th><th>أعلى سرعة</th><th>أقل سرعة (التقرير)</th><th>أقصى طول</th></tr></thead><tbody>{body}</tbody></table></div>'

def telnet_block():
    body = "".join(f"<tr><td class='mono'>{a}</td><td>{E(b)}</td><td>{E(c)}</td><td class='mono'>{E(d)}</td></tr>" for a, b, c, d in TELNET_REPORT)
    return ('<div class="callout warn"><b>غير متحقق منه</b><p>هذا الجدول ملخص لجدول الرسائل في تقريرك (48 رسالة). سأستبدله بمستكشف حزم حقيقي فور وصول ملف الالتقاط.</p></div>'
            f'<div class="tbl"><table><thead><tr><th>الرسالة</th><th>الاتجاه</th><th>المحتوى</th><th>الطول (بايت)</th></tr></thead><tbody>{body}</tbody></table></div>')

# ------------------------------------------------------------------ guide page
def guide_page(g):
    st = STATUS[g["status"]]
    toc, sec = [], []
    def H(id_, title, body):
        toc.append((id_, title)); sec.append(f'<section id="{id_}" class="sec"><h2>{E(title)}</h2>{body}</section>')

    learn = "".join(f"<li>{E(x)}</li>" for x in g["learn"])
    H("overview", "نظرة عامة", f'<ul class="learn">{learn}</ul>')
    if g["tools"] or g["tool_note"]:
        rows = "".join(f'<li class="tool"><a href="{E(link(k)[1])}" rel="noopener"><b>{E(link(k)[0])}</b><span>{E(role)}</span><span class="url mono" dir="ltr">{E(re.sub(r"^https?://", "", link(k)[1]).split("/")[0])}</span></a></li>' for k, role in g["tools"])
        H("software", "البرامج", (f'<ul class="tools">{rows}</ul>' if rows else "") + (f'<div class="callout note"><p>{g["tool_note"]}</p></div>' if g["tool_note"] else ""))
    if g["install"]:
        items = "".join(f'<li><h3>{E(t)}</h3><p>{b}</p>{code(*c) if c else ""}</li>' for t, b, c in g["install"])
        H("install", "التثبيت والتجهيز", f'<ol class="steps">{items}</ol>')
    if g["topo"]:
        H("diagram", "المخطط", topo_svg(g["topo"]) + (f'<p class="muted">{g["ip_note"]}</p>' if g["ip_note"] else ""))
    if g["steps"]:
        items = []
        for t, b, c, ex in g["steps"]:
            exl = "".join(f'<li><code dir="ltr">{E(k)}</code><span>{E(v)}</span></li>' for k, v in ex)
            items.append(f'<li><h3>{E(t)}</h3>' + (f"<p>{b}</p>" if b else "") + (code(*c) if c else "") + (f'<ul class="explain">{exl}</ul>' if exl else "") + "</li>")
        H("steps", "التنفيذ خطوة بخطوة", f'<ol class="steps">{"".join(items)}</ol>')
    if g["slug"] == "tcp-piggybacking" or g["slug"] == "tcp-retransmission":
        H("calc", "الحساب", piggy_block() if g["slug"] == "tcp-piggybacking" else retx_block())
    if g["slug"] == "ethernet-history":
        H("table", "الجدول", eth_block())
    if g["slug"] == "telnet":
        H("messages", "رسائل الجلسة (من التقرير)", telnet_block())
    if g["filters"]:
        fl = "".join(f'<li><code dir="ltr">{E(a)}</code><span>{E(b)}</span></li>' for a, b in g["filters"])
        H("filters", "فلاتر Wireshark", f'<ul class="explain">{fl}</ul>')
    if g["cap"]:
        caps = [(g["cap"], "مستكشف الحزم")] + ([(g["cap2"], "مستكشف الحزم · InterVLAN")] if g.get("cap2") else [])
        H("explorer", "مستكشف الحزم", '<p class="muted">اختر إطارًا لترى حقوله. مرّر المؤشر على أي حقل ليظهر مكانه في البايتات.</p>' + "".join(explorer_block(c, l) for c, l in caps))
    if g["slug"] in FINDINGS:
        fs = FINDINGS[g["slug"]]()
        items = []
        for f in fs:
            t, b, refs = f[0], f[1], f[2]
            capk = f[3] if len(f) > 3 else g["cap"]
            items.append(f'<li><h3>{E(t)}</h3><p>{b}</p>' + (f'<p class="refs">المصدر: {" ".join(fref(n, capk) for n in refs)}</p>' if refs else "") + "</li>")
        H("results", "النتائج من الالتقاط", f'<ul class="findings">{"".join(items)}</ul>')
    if g["cap"] and g["slug"] in ("ftp", "ftp-bulk", "smtp-pop3"):
        H("tcpcheck", "التحقق الآلي من TCP", checks_block(g["cap"]))
    vl = "".join(f'<li><input type="checkbox" id="v-{g["slug"]}-{i}"><label for="v-{g["slug"]}-{i}">{E(v)}</label></li>' for i, v in enumerate(g["verify"]))
    H("verify", "قائمة التحقق", f'<ul class="checklist">{vl}</ul>')
    if g["errors"]:
        er = "".join(f'<details class="err"><summary>{E(a)}</summary><p><b>السبب:</b> {b}</p><p><b>الحل:</b> {c}</p></details>' for a, b, c in g["errors"])
        H("errors", "أخطاء شائعة وحلولها", er)
    rf = "".join(f'<li><a href="{E(u)}" rel="noopener">{E(t)}</a></li>' for t, u in g["refs"])
    H("refs", "المراجع", f'<ul class="refs-l">{rf}</ul>')
    H("linkedin", "ملخص LinkedIn",
      f'<div class="li"><div class="li-c"><div class="li-h"><b>العربية</b><button type="button" class="copy" data-copy="li-ar-{g["slug"]}">نسخ</button></div><p id="li-ar-{g["slug"]}">{E(g["li_ar"])}</p></div>'
      f'<div class="li-c" dir="ltr" lang="en"><div class="li-h"><b>English</b><button type="button" class="copy" data-copy="li-en-{g["slug"]}">Copy</button></div><p id="li-en-{g["slug"]}">{E(g["li_en"])}</p></div></div>')

    ordered = sorted(GUIDES, key=lambda x: x["order"]); i = ordered.index(g)
    prv = ordered[i - 1] if i > 0 else None; nxt = ordered[i + 1] if i < len(ordered) - 1 else None
    pn = ('<nav class="pn" aria-label="التنقل بين الأدلة">' + (f'<a href="../{prv["slug"]}/"><span>السابق</span><b>{E(prv["title"])}</b></a>' if prv else "<span></span>")
          + (f'<a class="nx" href="../{nxt["slug"]}/"><span>التالي</span><b>{E(nxt["title"])}</b></a>' if nxt else "") + "</nav>")
    tocl = "".join(f'<li><a href="#{a}">{E(b)}</a></li>' for a, b in toc)
    main = (f'<div class="doc-head"><p class="crumb"><span class="mono">{g["course"]}</span> · دليل {g["order"]} من {len(GUIDES)}</p><h1>{E(g["title"])}</h1>'
            f'<p class="en" lang="en" dir="ltr">{E(g["en"])}</p><p class="lead">{E(g["summary"])}</p>'
            f'<p class="badge st-{st[0]}"><span class="dot st-{st[0]}"></span>{st[1]}<span class="b-n">{st[2]}</span></p></div>' + "".join(sec) + pn)
    page = (head(f'{g["title"]} · Fahad Net Lab', g["summary"], 2)
            + f'<div class="docs">{sidebar(g["slug"])}<main id="main" class="doc">{main}</main><aside class="toc" aria-label="في هذه الصفحة"><p>في هذه الصفحة</p><ul>{tocl}</ul></aside></div>'
            + FOOT.replace("{pre}", "../../"))
    d = os.path.join(ROOT, "guides", g["slug"]); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "index.html"), "w").write(page)

def retx_block():
    seq4, seq6 = 2046860036, 2046860048
    t = [("#7 S4", "عميل → خادم", seq4, 12, "يضيع"), ("RTO", "", None, None, "ينتهي المؤقت"), ("#7 S4", "عميل → خادم", seq4, 12, "إعادة إرسال · Checksum 0xAAB3 (التقرير)"),
         ("#8 S5", "خادم → عميل", 3535721162, 33, f"Ack = {seq4} + 12 = {seq4 + 12}"), ("#9 S6", "عميل → خادم", seq6, 6, "يضيع"), ("RTO", "", None, None, "ينتهي المؤقت"),
         ("#9 S6", "عميل → خادم", seq6, 6, "إعادة إرسال · Checksum 0x4033 (التقرير)")]
    body = "".join(f'<tr><td class="mono">{a}</td><td>{b}</td><td class="mono">{c if c else ""}</td><td class="mono">{d if d else ""}</td><td>{E(e)}</td></tr>' for a, b, c, d, e in t)
    return f'<div class="tbl"><table><thead><tr><th>الحدث</th><th>الاتجاه</th><th>Seq</th><th>Len</th><th>ملاحظة</th></tr></thead><tbody>{body}</tbody></table></div><div class="callout note"><p>لرؤية إعادة إرسال حقيقية ملتقطة، افتح <a href="../smtp-pop3/#tcpcheck">التحقق الآلي في مشروع SMTP و POP3</a>.</p></div>'

if __name__ == "__main__":
    for g in GUIDES:
        guide_page(g)
        print("built", g["slug"])
    # facts for the landing story, all read from captures
    story = {}
    fa = frames("icmp-arp"); ff = frames("ftp"); fi = frames("intervlan")
    story["arp"] = [S(fa, 1)["info"], S(fa, 2)["info"]]
    story["ping"] = {"req": len(find(fa, icmp_type=8)), "rep": len(find(fa, icmp_type=0)), "ttl": find(fa, icmp_type=0)[0]["ttl"]}
    syn = find(ff, flags="SYN", dport=21)[0]; sa = find(ff, flags="SYN ACK", sport=21)[0]; ak = S(ff, 4)
    story["hs"] = [(syn["seq"], 0), (sa["seq"], sa["ack"]), (ak["seq"], ak["ack"])]
    q = find(fi, icmp_type=8)
    story["iv"] = [(q[0]["vlan"], q[0]["ttl"]), (q[1]["vlan"], q[1]["ttl"])]
    story["macs"] = {"A": S(fa, 1)["src_mac"], "B": S(fa, 2)["src_mac"]}
    story["hex_frame"] = frames("icmp-arp")[2]["hex"]
    json.dump(story, open(os.path.join(ROOT, "tools", "story.json"), "w"), ensure_ascii=False, indent=1)
    print("story", story["ping"], story["hs"], story["iv"])
