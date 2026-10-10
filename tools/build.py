# -*- coding: utf-8 -*-
"""Build the static site: guides/<slug>/index.html from content.py + the captures.
Run from the repo root:  python3 -I tools/build.py"""
import base64, html, json, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from decode import load, tcp_checks
import content as CA, content_en as CE
from content import PIGGY
LANG = "en"
def t(ar, en):
    return en if LANG == "en" else ar
def C():
    return CE if LANG == "en" else CA
def OUT():
    return ROOT if LANG == "en" else os.path.join(ROOT, "ar")
NOTE_EN = {"0 في الالتقاط: كرت الشبكة يعبّيها بعدين (TCP Segmentation Offload)": "0 in the capture: the network card fills it in later (TCP Segmentation Offload)", "أكبر من الإطار": "larger than the frame"}

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
    return f'<button class="fref" data-frame="{n}"{c} type="button">{t("الإطار", "Frame")} {n}</button>'

def first_line(t, n=46):
    t = (t or "").split("\r\n")[0].strip()
    return t if len(t) <= n else t[:n - 1] + "…"

# ------------------------------------------------------------------ what each capture shows
def findings_ftp():
    fr = frames("ftp"); R = []
    syn = find(fr, flags="SYN", dport=21)[0]; sa = find(fr, flags="SYN ACK", sport=21)[0]
    R.append((t("المصافحة الثلاثية", "Three-way handshake"), t(f"SYN يبدأ بـ Seq {syn['seq']}، والخادم يرد بـ Ack {sa['ack']}، أي {syn['seq']} + 1.", f"SYN starts at Seq {syn['seq']} and the server answers with Ack {sa['ack']}, that is {syn['seq']} + 1."), [syn['no'], sa['no']]))
    for s in [f["s"] for f in fr if (f["s"].get("payload_txt") or "").startswith("227")]:
        tx = s["payload_txt"]; m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", tx)
        p1, p2 = int(m.group(5)), int(m.group(6)); port = p1 * 256 + p2
        syn2 = find(fr, flags="SYN", dport=port)
        R.append((t(f"منفذ البيانات {port}", f"Data port {port}"), f"<code>{E(tx.strip())}</code><br>{p1} × 256 + {p2} = <b>{port}</b>" + t("، وفي الإطار التالي يفتح العميل اتصالًا جديدًا على هذا المنفذ.", ", and in the next frame the client opens a new connection to that port."), [s['no']] + ([syn2[0]['no']] if syn2 else [])))
    lst = [f["s"] for f in fr if f["s"].get("sport") == 49672 and f["s"].get("plen", 0) > 0]
    if lst:
        R.append((t("قائمة الملفات", "The file list"), t(f"قناة البيانات حملت {lst[0]['plen']} بايت: ", f"The data channel carried {lst[0]['plen']} bytes: ") + f"<code>{E(lst[0]['payload_txt'].strip())}</code>", [lst[0]['no']]))
    retr = find(fr, payload_txt=lambda v: bool(v) and v.startswith("RETR")); size = find(fr, payload_txt=lambda v: bool(v) and v.startswith("213"))
    if retr:
        R.append((t("تحميل ملف فارغ", "Downloading an empty file"), f"<code>{E(retr[0]['payload_txt'].strip())}</code> " + t("بعد رد SIZE ", "after the SIZE reply ") + f"<code>{E(size[0]['payload_txt'].strip())}</code>" + t("، فانفتح اتصال البيانات وانقفل بدون بيانات.", ", so the data connection opened and closed with no data."), [size[0]['no'], retr[0]['no']]))
    pw = find(fr, payload_txt=lambda v: bool(v) and v.startswith("PASS"))[0]
    R.append((t("كلمة المرور مكشوفة", "The password is exposed"), f"<code>{E(pw['payload_txt'].strip())}</code> " + t("تمر نصًا واضحًا. في الدخول المجهول هي بريد شكلي، لكن أي حساب حقيقي ينكشف بنفس الطريقة.", "crosses the network in plain text. For an anonymous login it is a placeholder, but a real account would be exposed the same way."), [pw['no']]))
    return R

def findings_bulk():
    fr = frames("ftp-bulk"); R = []
    size = find(fr, payload_txt=lambda v: bool(v) and v.startswith("213"))[0]; retr = find(fr, payload_txt=lambda v: bool(v) and v.startswith("RETR"))[0]
    R.append((t("الحجم قبل التحميل", "Size before download"), f"<code>{E(retr['payload_txt'].strip())}</code> " + t("سبقه SIZE، والرد ", "was preceded by SIZE, and the reply was ") + f"<code>{E(size['payload_txt'].strip())}</code>.", [size['no'], retr['no']]))
    big = max((f["s"] for f in fr if f["s"].get("proto") == "TCP"), key=lambda s: s["plen"])
    ack = find(fr, ack=big["seq"] + big["plen"], dport=big["sport"])[0]
    R.append((t("الملف كله في إطار واحد", "The whole file in one frame"), t(f"{big['length']} بايت، منها {big['plen']} بيانات تبدأ من Seq {big['seq']}. العميل يرد بـ Ack {ack['ack']} = {big['seq']} + {big['plen']}.", f"{big['length']} bytes, {big['plen']} of them data starting at Seq {big['seq']}. The client answers with Ack {ack['ack']} = {big['seq']} + {big['plen']}."), [big['no'], ack['no']]))
    if big.get("tso"):
        R.append((t("لماذا Total Length = 0؟", "Why is Total Length 0?"), t("الالتقاط تم على الخادم نفسه. نظام التشغيل يسلّم بطاقة الشبكة كتلة كبيرة، والبطاقة هي التي تقسمها لمقاطع بحجم MSS وتكتب الطول (TCP Segmentation Offload). Wireshark رأى الكتلة قبل التقسيم.", "The capture ran on the server itself. The OS hands the network card one large block, and the card splits it into MSS-sized segments and writes the length (TCP Segmentation Offload). Wireshark saw the block before the split."), [big['no']]))
    rst = find(fr, flags=lambda v: bool(v) and "RST" in v)
    if rst:
        R.append((t("الإغلاق", "The close"), t(f"الخادم ينهي قناة البيانات بـ FIN، والعميل يقطعها بـ {rst[-1]['flags']}.", f"The server ends the data channel with FIN, and the client cuts it with {rst[-1]['flags']}."), [rst[-1]['no']]))
    return R

def findings_smtp():
    fr = frames("smtp"); R = []
    p = find(fr, payload_txt=lambda v: bool(v) and v.startswith("334"))
    R.append((t("Base64 ليس تشفيرًا", "Base64 is not encryption"), t("الخادم يطلب البيانات بنصوص مشفرة ظاهريًا: ", "The server asks for the credentials in text that only looks encrypted: ") + t("، ", ", ").join(f"<code>{E(s['payload_txt'][4:].strip())}</code> = <code>{E(base64.b64decode(s['payload_txt'][4:].strip()).decode())}</code>" for s in p) + t(". والعميل يرد بنفس الطريقة، فاسم المستخدم وكلمة المرور تُفك فورًا.", ". The client answers the same way, so the user name and password decode instantly."), [s['no'] for s in p]))
    mf = find(fr, payload_txt=lambda v: bool(v) and v.startswith("MAIL FROM"))[0]
    data = [f["s"] for f in fr if f["s"].get("dport") == 587 and f["s"].get("plen", 0) > 100][0]
    rt = find(fr, payload_txt=lambda v: bool(v) and v.startswith("+OK 529"))[0]
    R.append((t("403 بايت أرسلت، 529 وصلت", "403 bytes sent, 529 received"), f"<code>{E(mf['payload_txt'].strip())}</code>" + t(f"، والرسالة في إطار واحد طوله {data['plen']} بايت. وعند الاستلام: <code>+OK 529 octets</code>. الفرق هو ترويسات Return-Path و Received التي أضافها الخادم.", f", and the message went in one {data['plen']}-byte frame. On retrieval: <code>+OK 529 octets</code>. The difference is the Return-Path and Received headers the server added."), [mf['no'], data['no'], rt['no']]))
    rows = tcp_checks(fr)
    rx = []
    for r in rows:
        if r["seq_status"] == "retx":
            prev = [x for x in rows if x["no"] < r["no"] and x["dir"] == r["dir"] and x["seq"] == r["seq"] and x["len"] > 0]
            rx.append((prev[-1]["no"] if prev else None, r["no"], r["seq"]))
    if rx:
        R.append((t(f"{len(rx)} إعادات إرسال حقيقية", f"{len(rx)} real retransmissions"), t("نفس البايتات انرسلت مرتين بنفس رقم التسلسل: ", "The same bytes were sent twice with the same sequence number: ") + t("، ", ", ").join(t(f"الإطار {a} ثم {b}", f"frame {a} then {b}") for a, b, _ in rx) + ".", [n for a, b, _ in rx for n in (a, b) if n]))
    return R

def findings_arp():
    fr = frames("icmp-arp"); R = []
    a1, a2 = S(fr, 1), S(fr, 2)
    R.append((t("سؤال للجميع وجواب مباشر", "Ask everyone, answer one"), t(f"{E(a1['info'])} يخرج إلى ff:ff:ff:ff:ff:ff، والجواب {E(a2['info'])} يرجع مباشرة.", f"{E(a1['info'])} goes to ff:ff:ff:ff:ff:ff, and the answer {E(a2['info'])} comes straight back."), [1, 2]))
    R.append((t("60 بايت مقابل 42", "60 bytes vs 42"), t(f"الطلب وصل للخادم بطول {a1['length']} بايت ومعه 18 بايت Padding. أما الرد فطوله {a2['length']} لأنه التُقط على الخادم قبل أن تضيف بطاقته الحشو.", f"The request reached the server as {a1['length']} bytes including 18 bytes of padding. The reply shows as {a2['length']} because it was captured on the server before its card added the padding."), [1, 2]))
    req = find(fr, icmp_type=8); rep = find(fr, icmp_type=0)
    R.append((t(f"{len(req)} طلبات، {len(rep)} ردود", f"{len(req)} requests, {len(rep)} replies"), t("أرقام التسلسل ", "Sequence numbers ") + t("، ", ", ").join(str(s['icmp_seq']) for s in req) + t(f"، وكل رد بـ TTL {rep[0]['ttl']} و {req[0]['icmp_dlen']} بايت بيانات.", f"; every reply has TTL {rep[0]['ttl']} and {req[0]['icmp_dlen']} bytes of data."), [req[0]['no'], rep[0]['no']]))
    R.append((t("فرق Checksum ثابت", "A constant checksum difference"), " · ".join(t(f"{q['icmp_ck']} ← {p['icmp_ck']}", f"{q['icmp_ck']} → {p['icmp_ck']}") for q, p in zip(req, rep)) + t(". الفرق دائمًا 0x0800 لأن الحقل الوحيد الذي تغير هو Type من 8 إلى 0.", ". The difference is always 0x0800, because the only field that changed is Type, from 8 to 0."), [req[0]['no'], rep[0]['no']]))
    tail = [f["s"] for f in fr[10:12]]
    R.append((t("الخادم يسأل أيضًا", "The server asks too"), t(f"بعد الردود: {E(tail[0]['info'])}. كل طرف يحتفظ بجدول ARP خاص به.", f"After the replies: {E(tail[0]['info'])}. Each side keeps its own ARP table."), [tail[0]['no'], tail[1]['no']]))
    return R

def findings_vlan():
    fr = frames("vlan"); fi = frames("intervlan"); R = []
    k = {}
    for f in fr:
        k[f["s"].get("proto")] = k.get(f["s"].get("proto"), 0) + 1
    R.append((t("السويتشات تتكلم دائمًا", "The switches are always talking"), t(f"من {len(fr)} إطارًا على الـ Trunk: {k.get('STP',0)} إطار STP و {k.get('PVST+',0)} إطار PVST+ و {k.get('CDP',0)} CDP، قبل أي حركة من المستخدمين.", f"Of {len(fr)} frames on the trunk: {k.get('STP',0)} STP, {k.get('PVST+',0)} PVST+ and {k.get('CDP',0)} CDP, before any user traffic."), []))
    ping = find(fr, icmp_type=8)[0]; pong = find(fr, icmp_type=0)[0]
    R.append((t("78 بايت بدل 74", "78 bytes instead of 74"), t(f"طلب ping داخل VLAN {ping['vlan']} طوله {ping['length']} بايت: الأربعة الزائدة هي وسم 802.1Q.", f"A ping request inside VLAN {ping['vlan']} is {ping['length']} bytes: the extra four are the 802.1Q tag."), [ping['no'], pong['no']]))
    rq = find(fi, icmp_type=8); rp = find(fi, icmp_type=0); a, b = rq[0], rq[1]
    R.append((t("نفس الطلب مرتين على الـ Trunk", "The same request crosses the trunk twice"), t(f"قبل الراوتر: VID {a['vlan']} · TTL {a['ttl']}<br>بعد الراوتر: VID {b['vlan']} · TTL {b['ttl']}<br>عنوانا IP ثابتان، والـ Checksum {a['icmp_ck']} لم يتغير.", f"Before the router: VID {a['vlan']} · TTL {a['ttl']}<br>After the router: VID {b['vlan']} · TTL {b['ttl']}<br>Both IP addresses stay the same, and the ICMP checksum {a['icmp_ck']} does not change."), [a['no'], b['no']], "intervlan"))
    R.append((t("MAC يتغير في كل قفزة", "The MAC changes at every hop"), t(f"{a['src_mac']} ← {a['dst_mac']} ثم {b['src_mac']} ← {b['dst_mac']}. الراوتر يكتب عنوانه مصدرًا في الإطار الجديد.", f"{a['src_mac']} → {a['dst_mac']}, then {b['src_mac']} → {b['dst_mac']}. The router writes its own MAC as the source of the new frame."), [a['no'], b['no']], "intervlan"))
    R.append((t("الرد بنفس الطريق", "The reply takes the same path"), t(f"VID {rp[0]['vlan']} · TTL {rp[0]['ttl']} ثم VID {rp[1]['vlan']} · TTL {rp[1]['ttl']}.", f"VID {rp[0]['vlan']} · TTL {rp[0]['ttl']}, then VID {rp[1]['vlan']} · TTL {rp[1]['ttl']}."), [rp[0]['no'], rp[1]['no']], "intervlan"))
    return R


# ------------------------------------------------------------------ Telnet helpers
TN_CLIENT, TN_SERVER = "189.120.0.57", "189.120.0.58"
def tn_bytes(f):
    s = f["s"]; L = s.get("plen") or 0
    h = f["hex"]; ip_end = 14 + 20 + 20  # placeholder, real offset computed below
    raw = bytes.fromhex(h)
    # payload = last plen bytes before Ethernet padding: locate from TCP header
    ihl = (raw[14] & 15) * 4; tot = int.from_bytes(raw[16:18], "big"); thl = (raw[14 + ihl + 12] >> 4) * 4
    start = 14 + ihl + thl
    return raw[start:14 + tot]

def tn_phases():
    """Split the Telnet capture into phases by content. Returns dict of frame lists."""
    fr = frames("telnet"); P = {"user": [], "pw": [], "pw_ack": [], "exit": []}; state = "pre"
    for f in fr:
        s = f["s"]
        if s.get("proto") != "TCP": continue
        b = tn_bytes(f); cli = s["src"] == TN_CLIENT
        if not cli and b"login:" in b: state = "user"; P["login"] = s["no"]; continue
        if not cli and b"password:" in b: state = "pw"; P["pwprompt"] = s["no"]; continue
        if not cli and b"\x1b[" in b and len(b) > 200: P["screen"] = s["no"]; state = "shell"; continue
        if state == "user" and len(b) == 1: P["user"].append(s["no"])
        if state == "user" and cli and b == b"\r\n": P["user_end"] = s["no"]
        if state == "pw" and cli and len(b) == 1: P["pw"].append(s["no"])
        if state == "pw" and not cli and not b: P["pw_ack"].append(s["no"])
        if state == "pw" and not cli and len(b) == 1: P["pw_echo"] = True
        if state == "pw" and cli and b == b"\r\n": P["pw_end"] = s["no"]; state = "post"
        if state == "shell" and len(b) == 1: P["exit"].append(s["no"])
        if state == "shell" and cli and b == b"\r\n": P["exit_end"] = s["no"]
        if "FIN" in s["flags"] and "fin" not in P: P["fin"] = s["no"]; P["fin_by"] = "server" if not cli else "client"
        if b.startswith(b"\xff\xfa\x18\x00"): P["ttype"] = s["no"]; P["ttype_val"] = b[4:-2].decode("ascii", "replace")
        if b.startswith(b"\xff\xfa\x25") and b"NTLMSSP\x00" in b:
            P.setdefault("ntlm", []).append((s["no"], len(b), b[b.index(b"NTLMSSP\x00") + 8]))
        if b"\xff\xfa\x1f" in b:
            i = b.index(b"\xff\xfa\x1f"); P["naws"] = (s["no"], int.from_bytes(b[i+3:i+5], "big"), int.from_bytes(b[i+5:i+7], "big"), b[i:i+9].hex(" "))
        if b.startswith(b"\xff\xfa\x27\x00") and b"SFUTLNTMODE" in b:
            P["env"] = s["no"]; P["env_mode"] = b.split(b"SFUTLNTMODE\x01")[1].split(b"\xff")[0].decode()
    first = next(f for f in fr if f["s"].get("plen") and f["s"]["src"] == TN_SERVER)
    b = tn_bytes(first); P["first"] = (first["s"]["no"], len(b), sum(1 for i in range(0, len(b), 3) if b[i] == 0xff))
    P["user_txt"] = "".join(chr(tn_bytes(next(f for f in fr if f["s"]["no"] == n))[0]) for n in P["user"] if frames("telnet")[n-1]["s"]["src"] == TN_CLIENT)
    return P

def findings_telnet():
    P = tn_phases(); R = []
    n, ln, k = P["first"]
    R.append((t(f"{k} طلبات في رسالة واحدة", f"{k} requests in one message"), t(f"أول ما أرسله الخادم {ln} بايت: {k} أوامر IAC، كل أمر 3 بايتات، قبل أي نص على الشاشة.", f"The server's first {ln} bytes hold {k} IAC commands of 3 bytes each, before any text on screen."), [n]))
    no, c, r, hx = P["naws"]
    R.append((t(f"نافذة {c} × {r}", f"A {c} × {r} window"), t("العميل أعلن حجم شاشته: ", "The client announced its screen size: ") + f"<code dir=\"ltr\">{hx}</code>.", [no]))
    nt = P["ntlm"]; names = {1: "Negotiate", 2: "Challenge", 3: "Authenticate"}
    R.append((t("NTLM ثم الرفض", "NTLM, then a refusal"), t("ثلاث رسائل NTLMSSP: ", "Three NTLMSSP messages: ") + t("، ثم ", ", then ").join(t(f"{names.get(ty, ty)} بحجم {l} بايت", f"{names.get(ty, ty)} ({l} bytes)") for _, l, ty in nt) + t(". محتوى الرسالتين الأخيرتين مُصفّر في الملف المنشور.<br>بعدها رد الخادم: ", ". The content of the last two is zeroed in the published file.<br>Then the server replied: ") + "<span dir=\"ltr\">Telnet server could not log you in using NTLM authentication.</span>", [x[0] for x in nt] + [P["login"]]))
    nu = len(P["user_txt"])
    R.append((t("اسم المستخدم يعود، كلمة المرور لا", "The user name echoes, the password doesn't"), t(f"اسم المستخدم {nu} حروف، كل حرف في مقطع والخادم يعيده. كلمة المرور {len(P['pw'])} ضغطة، والخادم يرد على كل واحدة بـ ACK فقط. لكن الحروف نفسها تمر بنص واضح، لذلك استُبدلت بـ * في الملف المنشور.", f"The user name is {nu} characters, each in its own segment and echoed back. The password is {len(P['pw'])} keystrokes, each answered with a bare ACK. The characters themselves still cross in plain text, so they are replaced with * in the published file."), [P["user"][0], P["user"][1], P["pw"][0], P["pw_ack"][0]]))
    R.append((t(f"الطرفية {P['ttype_val']} والشاشة", f"{P['ttype_val']} terminal and the screen"), t(f"بعد الدخول طلب الخادم نوع الطرفية فأجاب العميل {P['ttype_val']}، ثم أرسل الخادم الشاشة كاملة في {frames('telnet')[P['screen']-1]['s']['plen']} بايت بأوامر ANSI لتحديد مكان كل سطر.", f"After login the server asked for the terminal type and the client answered {P['ttype_val']}; the server then sent the whole screen in {frames('telnet')[P['screen']-1]['s']['plen']} bytes, using ANSI codes to place each line."), [P["ttype"], P["screen"]]))
    R.append((t("الخادم يغلق أولًا", "The server closes first"), t(f"بعد <code>exit</code> أرسل {'الخادم' if P['fin_by'] == 'server' else 'العميل'} FIN، ثم أغلق الطرف الآخر.", f"After <code>exit</code> the {P['fin_by']} sent FIN, then the other side closed."), [P["fin"]]))
    return R

FINDINGS = {"telnet": findings_telnet, "ftp": findings_ftp, "ftp-bulk": findings_bulk, "smtp-pop3": findings_smtp, "arp-icmp": findings_arp, "vlan-intervlan": findings_vlan}

# ------------------------------------------------------------------ sequence diagrams
def flow_html(cols, rows, cap=None, note=""):
    """cols: list of labels (index 0 drawn on the right). rows: dicts {a,b,label,sub,no,cls}."""
    n = len(cols)
    x = (lambda i: (i + .5) / n * 100) if LANG == "en" else (lambda i: (1 - (i + .5) / n) * 100)
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
            lab = t(f"بيانات · {s['plen']} بايت", f"data · {s['plen']} bytes")
        rows.append({"a": hosts.index(s["src"]), "b": hosts.index(s["dst"]), "label": lab + (t("  ↺ إعادة إرسال", "  ↺ retransmission") if s["no"] in retx else ""),
                     "sub": f"Seq {s['seq']} · Ack {s['ack']} · Len {s['plen']}", "no": s["no"], "cls": "rx" if s["no"] in retx else ("ctl" if not s["plen"] else "")})
    return rows[:limit] if limit else rows

def flow_block(g):
    if g["slug"] == "ftp":
        return flow_html([t("العميل 189.120.0.57", "Client 189.120.0.57"), t("الخادم 189.120.0.58", "Server 189.120.0.58")], flow_tcp("ftp", ["189.120.0.57", "189.120.0.58"], limit=34), "ftp", t("اضغط أي سهم لفتح الإطار في مستكشف الحزم.", "Click any arrow to open the frame in the packet explorer."))
    if g["slug"] == "ftp-bulk":
        return flow_html([t("العميل 189.120.0.57", "Client 189.120.0.57"), t("الخادم 189.120.0.58", "Server 189.120.0.58")], flow_tcp("ftp-bulk", ["189.120.0.57", "189.120.0.58"]), "ftp-bulk", t("اضغط أي سهم لفتح الإطار.", "Click any arrow to open the frame."))
    if g["slug"] == "smtp-pop3":
        rows = flow_tcp("smtp", ["189.120.0.57", "189.120.0.58", "189.120.0.59"], ports=(587, 110))
        rows = [dict(r, b=r["b"], a=r["a"]) for r in rows]
        return flow_html([t("المرسل .57", "Sender .57"), t("خادم البريد .58", "Mail server .58"), t("المستقبل .59", "Receiver .59")], rows, "smtp", t("اضغط أي سهم لفتح الإطار.", "Click any arrow to open the frame."))
    if g["slug"] == "arp-icmp":
        fr = frames("icmp-arp"); H = ["189.120.0.57", "189.120.0.58"]; rows = []
        for f in fr:
            s = f["s"]
            if s.get("proto") in ("ARP", "ICMP") and s["src"] in H and s["dst"] in H:
                lab = ("ARP · " + (t("من يملك " + s["dst"] + "؟", "who has " + s["dst"] + "?") if "Who" in s["info"] else t("أنا " + s["src"], s["src"] + " is here"))) if s["proto"] == "ARP" else ("Echo request" if s["icmp_type"] == 8 else "Echo reply") + f" · seq {s['icmp_seq']}"
                rows.append({"a": H.index(s["src"]), "b": H.index(s["dst"]), "label": lab, "sub": t(f"{s['length']} بايت", f"{s['length']} bytes") + (f" · TTL {s['ttl']}" if s.get('ttl') else ""), "no": s["no"], "cls": "arp" if s["proto"] == "ARP" else ""})
        return flow_html([t("العميل 189.120.0.57", "Client 189.120.0.57"), t("الخادم 189.120.0.58", "Server 189.120.0.58")], rows, "icmp-arp", t("اضغط أي سهم لفتح الإطار.", "Click any arrow to open the frame."))
    if g["slug"] == "vlan-intervlan":
        fi = frames("intervlan"); M = {}
        rq = find(fi, icmp_type=8); rp = find(fi, icmp_type=0)
        A, R_, B = rq[0]["src_mac"], rq[0]["dst_mac"], rq[1]["dst_mac"]
        idx = {A: 0, R_: 1, B: 2}
        rows = [{"a": idx[s["src_mac"]], "b": idx[s["dst_mac"]], "label": ("Echo request" if s["icmp_type"] == 8 else "Echo reply") + f" · VID {s['vlan']}", "sub": f"TTL {s['ttl']} · {s['src']} → {s['dst']}", "no": s["no"], "cls": "v10" if s["vlan"] == 10 else "v20"} for s in sorted(rq + rp, key=lambda s: s["no"])]
        return flow_html(["A · VLAN 10", "R · Router on a Stick", "B · VLAN 20"], rows, "intervlan", t("نفس الطلب يمر على الـ Trunk مرتين. اضغط أي سهم لفتح الإطار.", "The same request crosses the trunk twice. Click any arrow to open the frame."))
    if g["slug"] == "telnet":
        fr = frames("telnet"); P = tn_phases(); H = [TN_CLIENT, TN_SERVER]; rows = []
        names = {1: "NTLMSSP Negotiate", 2: "NTLMSSP Challenge", 3: "NTLMSSP Authenticate"}
        ntlm = {n: names.get(t) for n, _, t in P["ntlm"]}
        def add(n, label, cls=""):
            s = fr[n - 1]["s"]
            rows.append({"a": H.index(s["src"]), "b": H.index(s["dst"]), "label": label, "sub": f"Seq {s['seq']} · Ack {s['ack']} · Len {s['plen']}", "no": n, "cls": cls})
        def group(a, b, label, sub, n, cls="ctl"):
            rows.append({"a": a, "b": b, "label": label, "sub": sub, "no": n, "cls": cls})
        IAC = {0xfb: "WILL", 0xfc: "WONT", 0xfd: "DO", 0xfe: "DONT"}
        OPT = {0: "Binary", 1: "Echo", 3: "SGA", 0x18: "Terminal-Type", 0x1f: "NAWS", 0x25: "Auth", 0x27: "New-Environ"}
        def iac_label(b):
            out = []; i = 0
            while i < len(b) - 1:
                if b[i] == 0xff and b[i+1] in IAC: out.append(f"{IAC[b[i+1]]} {OPT.get(b[i+2], hex(b[i+2]))}"); i += 3
                elif b[i] == 0xff and b[i+1] == 0xfa:
                    j = b.find(b"\xff\xf0", i); opt = OPT.get(b[i+2], hex(b[i+2]))
                    if b[i+2] == 0x1f: extra = f" {int.from_bytes(b[i+3:i+5],'big')}×{int.from_bytes(b[i+5:i+7],'big')}"
                    else:
                        sub = {0: "IS", 1: "SEND", 2: "REPLY"}.get(b[i+3], "")
                        extra = f" {sub}" + (f" {b[i+4:j].decode('ascii','replace')}" if b[i+2] == 0x18 and b[i+3] == 0 else "")
                    lab = f"SB {opt}{extra}"
                    if not out or out[-1] != lab: out.append(lab)
                    i = j + 2 if j > 0 else len(b)
                else: break
            return " · ".join(out)
        skip = set(P["user"][2:] + P["pw"][1:] + P["pw_ack"][1:] + P["exit"][2:])
        for f in fr:
            s = f["s"]; n = s["no"]
            if s.get("proto") != "TCP" or n in skip: continue
            b = tn_bytes(f); fl = s["flags"]
            if n in ntlm: add(n, f"{ntlm[n]} · {len(b)} " + t("بايت", "bytes")); continue
            if not b:
                if any(k in fl for k in ("SYN", "FIN")) or n == 3: add(n, fl.replace(" ", "-"), "ctl")
                elif n == P["pw_ack"][0]:
                    add(n, t("ACK فقط · لا Echo", "ACK only · no echo"), "ctl")
                    group(0, 1, t(f"… {len(P['pw'])} ضغطة، كل واحدة بلا Echo", f"… {len(P['pw'])} keystrokes, none echoed"), t("الإطارات ", "frames ") + f"{P['pw'][0]}–{P['pw_ack'][-1]}", P["pw"][-1])
                continue
            if n == P["login"]: add(n, t("رفض NTLM · login:", "NTLM refused · login:")); continue
            if n == P["pwprompt"]: add(n, "password:"); continue
            if n == P["screen"]: add(n, t(f"شاشة الدخول · {len(b)} بايت", f"login screen · {len(b)} bytes")); continue
            if n == P.get("env"): add(n, f"SB New-Environ IS · MODE={P['env_mode']}"); continue
            if b[0] == 0xff: add(n, iac_label(b)); continue
            if n == P["pw"][0]:
                add(n, t("حرف من كلمة المرور · مخفي", "password character · hidden"), "sec"); continue
            if b == b"\r\n": add(n, "Enter · \\r\\n"); continue
            if n in P["user"][:2] or n in P["exit"][:2]:
                add(n, f"'{b.decode('latin-1')}'" + (" · Echo" if s["src"] == TN_SERVER else ""))
                if n == P["user"][1]: group(0, 1, t("… بقية اسم المستخدم حرفًا حرفًا مع Echo", "… rest of the user name, one character at a time with echo"), t("الإطارات ", "frames ") + f"{P['user'][2]}–{P['user'][-1]}", P["user"][2])
                if n == P["exit"][1]: group(0, 1, t("… x · i · t بنفس الطريقة", "… x · i · t the same way"), t("الإطارات ", "frames ") + f"{P['exit'][2]}–{P['exit'][-1]}", P["exit"][2])
                continue
            add(n, first_line(b.decode("latin-1")))
        return flow_html([t("العميل 189.120.0.57", "Client 189.120.0.57"), t("الخادم 189.120.0.58", "Server 189.120.0.58")], rows, "telnet", t("اضغط أي سهم لفتح الإطار في مستكشف الحزم.", "Click any arrow to open the frame in the packet explorer."))
    if g["slug"] == "tcp-piggybacking":
        p = PIGGY; rows = []; sa, sb = p["isn_a"] + 1, p["isn_b"] + 1
        for i in range(3):
            rows.append({"a": 1, "b": 0, "label": t(f"A{i+1} · {p['a'][i]} بايت + ACK", f"A{i+1} · {p['a'][i]} bytes + ACK"), "sub": f"Seq {sa} · Ack {sb}"}); sa += p["a"][i]
            rows.append({"a": 0, "b": 1, "label": t(f"B{i+1} · {p['b'][i]} بايت + ACK", f"B{i+1} · {p['b'][i]} bytes + ACK"), "sub": f"Seq {sb} · Ack {sa}"}); sb += p["b"][i]
        return flow_html([t("B · منفذ 1070", "B · port 1070"), t("A · منفذ 110", "A · port 110")], rows)
    if g["slug"] == "tcp-retransmission":
        rows = [{"a": 0, "b": 1, "label": t("S4 · 12 بايت", "S4 · 12 bytes"), "sub": "Seq 2046860036", "cls": "lost"},
                {"a": 0, "b": 1, "label": t("S4 مرة ثانية بعد RTO", "S4 again after RTO"), "sub": "Seq 2046860036 · Checksum 0xAAB3", "cls": "rx"},
                {"a": 1, "b": 0, "label": t("S5 · 33 بايت", "S5 · 33 bytes"), "sub": "Seq 3535721162 · Ack 2046860048"},
                {"a": 0, "b": 1, "label": t("S6 · 6 بايت", "S6 · 6 bytes"), "sub": "Seq 2046860048", "cls": "lost"},
                {"a": 0, "b": 1, "label": t("S6 مرة ثانية بعد RTO", "S6 again after RTO"), "sub": "Seq 2046860048 · Checksum 0x4033", "cls": "rx"}]
        return flow_html([t("العميل · 1070", "Client · 1070"), t("الخادم · 110", "Server · 110")], rows)
    return ""

# ------------------------------------------------------------------ html pieces
ICON = {
 "pc": '<rect x="-22" y="-16" width="44" height="28" rx="4"/><path d="M-28 16h56"/>',
 "server": '<rect x="-16" y="-22" width="32" height="44" rx="4"/><path d="M-9 -10h12M-9 0h12M-9 10h12"/><circle cx="9" cy="-10" r="1.8"/><circle cx="9" cy="0" r="1.8"/>',
 "switch": '<rect x="-30" y="-11" width="60" height="22" rx="5"/><path d="M-20 0h6M-8 0h6M4 0h6M16 0h6"/>',
 "router": '<ellipse cx="0" cy="-6" rx="24" ry="8"/><path d="M-24 -6v12a24 8 0 0 0 48 0v-12"/><path d="M-8 -6h16M0 -12v12"/>',
}

def topo_svg(tp):
    if not tp:
        return ""
    W, H = 820, 380 if len(tp["nodes"]) > 3 else 240
    pos = {n[0]: (n[4] * W, n[5] * H) for n in tp["nodes"]}
    out = [f'<svg class="topo" viewBox="0 0 {W} {H}" role="img" aria-label="{t('مخطط الشبكة', 'Network diagram')}">']
    for i, (a, b, lab) in enumerate(tp["links"]):
        (x1, y1), (x2, y2) = pos[a], pos[b]
        out.append(f'<line class="lk" x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}"/><circle class="pk" r="4"><animateMotion dur="{2.4 + i * .4}s" repeatCount="indefinite" path="M{x1:.0f},{y1:.0f} L{x2:.0f},{y2:.0f}"/></circle>')
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        out.append(f'<text class="lkl" x="{mx:.0f}" y="{my - 12:.0f}" text-anchor="middle">{E(lab)}</text>')
    for nid, name, sub, ip, x, y, kind in tp["nodes"]:
        X, Y = pos[nid]
        out.append(f'<g class="nd" transform="translate({X:.0f},{Y:.0f})"><circle class="halo" r="38"/><g class="ic">{ICON[kind]}</g>'
                   f'<text class="n1" y="54" text-anchor="middle">{E(name)}</text><text class="n2" y="72" text-anchor="middle">{E(sub)}</text>'
                   + (f'<text class="n3" y="90" text-anchor="middle">{E(ip)}</text>' if ip else "") + '</g>')
    out.append("</svg>")
    return "".join(out)

def code(lang, txt):
    return (f'<div class="code"><div class="code-h"><span>{E(lang)}</span><button type="button" class="copy">{t("نسخ", "Copy")}</button></div>'
            f'<pre dir="ltr"><code>{E(txt)}</code></pre></div>')

def link(k):
    return C().L[k] if isinstance(k, str) else k

def sidebar(active):
    out = [f'<nav class="side" aria-label="{t("المشاريع", "Projects")}">']
    for course, title in (("COS 370", t("بروتوكولات الشبكات", "Network Protocols")), ("COS 372", t("محاكاة الشبكات", "Network Simulation"))):
        out.append(f'<div class="side-g"><p class="side-h"><span class="mono">{course}</span> {title}</p><ul>')
        for g in sorted([g for g in C().GUIDES if g["course"] == course], key=lambda g: g["order"]):
            cur = ' aria-current="page"' if g["slug"] == active else ""
            out.append(f'<li><a href="../{g["slug"]}/"{cur}>{E(g["title"])}</a></li>')
        out.append("</ul></div>")
    out.append("</nav>")
    return "".join(out)

def head(title, desc, depth, other):
    pre = "../" * depth
    home = pre + ("ar/" if LANG == "ar" else "")
    return f"""<!doctype html>
<html lang="{LANG}" dir="{t('rtl', 'ltr')}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{E(title)}</title>
<meta name="description" content="{E(desc)}">
<meta property="og:title" content="{E(title)}">
<meta property="og:description" content="{E(desc)}">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%23111433'/%3E%3Cpath d='M9 22l7-12 7 12' stroke='%237C83FF' stroke-width='3' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Sans+Arabic:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap">
<link rel="stylesheet" href="{pre}assets/site.css">
<script>try{{var t=localStorage.getItem('fnl-theme');if(t)document.documentElement.dataset.theme=t}}catch(e){{}}</script>
</head>
<body>
<a class="skip" href="#main">{t("تخطَّ إلى المحتوى", "Skip to content")}</a>
<header class="top"><div class="top-in">
<a class="brand" href="{home}"><span class="logo" aria-hidden="true"></span><span>Fahad Net Lab</span></a>
<nav class="top-nav" aria-label="{t('الرئيسية', 'Main')}"><a href="{home}#story">{t('الشبكة', 'The network')}</a><a href="{home}#projects">{t('المشاريع', 'Projects')}</a><a href="{WP}" rel="noopener">{t('المدونة', 'Blog')}</a></nav>
<a class="lang" href="{other}" hreflang="{t('en', 'ar')}" lang="{t('en', 'ar')}">{t('English', 'العربية')}</a>
<button class="theme" type="button" aria-label="{t('تبديل المظهر', 'Toggle theme')}"><span aria-hidden="true"></span></button>
<button class="menu" type="button" aria-label="{t('قائمة المشاريع', 'Project menu')}" aria-expanded="false"><span aria-hidden="true"></span></button>
</div></header>"""

FOOT = """<footer class="foot"><div class="foot-in"><span>© 2026 {me} · Fahad Net Lab</span><span>{uni} · COS 370 · COS 372</span></div></footer>
<script src="{pre}assets/site.js" defer></script>
</body></html>"""

def explorer_block(capkey, label):
    fr = frames(capkey)
    data = [{"s": f["s"], "l": f["layers"], "h": f["hex"]} for f in fr]
    if LANG == "en":
        data = json.loads(json.dumps(data))
        for d in data:
            for ly in d["l"]:
                for fd in ly["fields"]:
                    if fd.get("note") in NOTE_EN: fd["note"] = NOTE_EN[fd["note"]]
    j = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    return (f'<div class="xp" data-cap="{capkey}"><div class="xp-h"><b>{E(label)}</b>'
            f'<a href="{PRE}captures/{capkey}.pcapng" download>{t("تحميل", "Download")} {capkey}.pcapng</a>'
            f'<label class="xp-f"><span class="sr">{t("بحث في الإطارات", "Search frames")}</span><input type="search" id="flt-{capkey}" placeholder="{t("ابحث: PASV، icmp، vlan…", "Search: PASV, icmp, vlan…")}" dir="auto"></label></div>'
            f'<div class="xp-b"><div class="xp-list" role="listbox" aria-label="{t("الإطارات", "Frames")}"></div><div class="xp-d"><div class="xp-tree"></div><div class="xp-hex" dir="ltr"></div></div></div>'
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
    return (f'<div class="tbl"><table><thead><tr><th>{t("المقطع", "Segment")}</th><th>Seq</th><th>Ack</th><th>Len</th><th>Window</th><th>Checksum</th></tr></thead><tbody>{body}</tbody></table></div>'
            f'<h3 class="sub-h">{t("هيدر A1 بالـ Hex", "A1 header in hex")}</h3><div class="hexcells" dir="ltr">{cells}</div>')

def eth_block():
    body = "".join(f"<tr><td class='mono'>{a}</td><td>{E(b)}</td><td class='mono'>{c}</td><td>{E(e)}</td></tr>" for a, b, c, d, e in C().ETH_TABLE)
    return f'<div class="tbl"><table><thead><tr><th>{t("السنة", "Year")}</th><th>{t("التقنية والمعيار", "Technology and standard")}</th><th>{t("السرعة", "Speed")}</th><th>{t("أقصى طول", "Max length")}</th></tr></thead><tbody>{body}</tbody></table></div>'

# ------------------------------------------------------------------ guide page
def guide_page(g):
    global PRE
    PRE = "../../../" if LANG == "ar" else "../../"
    toc, sec = [], []
    def H(id_, title, body, cls=""):
        toc.append((id_, title)); sec.append(f'<section id="{id_}" class="sec {cls}"><h2>{E(title)}</h2>{body}</section>')

    if g["tools"]:
        rows = "".join(f'<li class="tool"><a href="{E(link(k)[1])}" rel="noopener"><b>{E(link(k)[0])}</b><span>{E(role)}</span></a></li>' for k, role in g["tools"])
        H("software", t("البرامج", "Software"), f'<ul class="tools">{rows}</ul>' + (f'<p class="note">{g["tool_note"]}</p>' if g["tool_note"] else ""))
    if g["install"]:
        items = "".join(f'<li><h3>{E(tt)}</h3><p>{b}</p>{code(*c) if c else ""}</li>' for tt, b, c in g["install"])
        H("setup", t("التجهيز", "Setup"), f'<ol class="steps">{items}</ol>')
    if g["steps"]:
        items = []
        for tt, b, c, ex in g["steps"]:
            exl = "".join(f'<li><code dir="ltr">{E(k)}</code><span>{E(v)}</span></li>' for k, v in ex)
            items.append(f'<li><h3>{E(tt)}</h3>' + (f"<p>{b}</p>" if b else "") + (code(*c) if c else "") + (f'<ul class="explain">{exl}</ul>' if exl else "") + "</li>")
        H("steps", t("التنفيذ", "Steps"), f'<ol class="steps">{"".join(items)}</ol>')
    if g["filters"]:
        fl = "".join(f'<li><code dir="ltr">{E(a)}</code><span>{E(b)}</span></li>' for a, b in g["filters"])
        sec[-1] = sec[-1].replace("</section>", f'<h3 class="sub-h">{t("فلاتر مفيدة في Wireshark", "Useful Wireshark filters")}</h3><ul class="explain">{fl}</ul></section>')
    fb = flow_block(g)
    if fb:
        H("flow", t("مسار الجلسة", "Session flow"), fb, "wide")
    if g["slug"] == "tcp-piggybacking":
        H("calc", t("الأرقام", "The numbers"), piggy_block())
    if g["slug"] == "ethernet-history":
        H("table", t("المراحل", "Milestones"), eth_block())
    if g["cap"]:
        caps = [(g["cap"], t("داخل الحزم", "Inside the packets"))] + ([(g["cap2"], "InterVLAN")] if g.get("cap2") else [])
        H("explorer", t("داخل الحزم", "Inside the packets"), '<p class="muted">' + t("اختر إطارًا، ومرّر المؤشر على أي حقل ليظهر مكانه في البايتات.", "Pick a frame and hover any field to see where it sits in the bytes.") + '</p>' + "".join(explorer_block(c, l) for c, l in caps), "wide")
    if g["slug"] in FINDINGS:
        items = []
        for f in FINDINGS[g["slug"]]():
            tt, b, refs = f[0], f[1], f[2]; capk = f[3] if len(f) > 3 else g["cap"]
            items.append(f'<li><h3>{E(tt)}</h3><p>{b}</p>' + (f'<p class="refs">{" ".join(fref(n, capk) for n in refs)}</p>' if refs else "") + "</li>")
        H("results", t("ماذا كشف الالتقاط", "What the capture shows"), f'<ul class="findings">{"".join(items)}</ul>')
    if g["errors"]:
        er = "".join(f'<details class="err"><summary>{E(a)}</summary><p>{b}</p><p><b>{t('الحل:', 'Fix:')}</b> {c}</p></details>' for a, b, c in g["errors"])
        H("errors", t("مشاكل وحلول", "Troubleshooting"), er)
    rf = "".join(f'<li><a href="{E(u)}" rel="noopener">{E(tt)}</a></li>' for tt, u in g["refs"])
    H("refs", t("المراجع", "References"), f'<ul class="refs-l">{rf}</ul>')

    ordered = sorted(C().GUIDES, key=lambda x: x["order"]); i = ordered.index(g)
    prv = ordered[i - 1] if i > 0 else None; nxt = ordered[i + 1] if i < len(ordered) - 1 else None
    pn = (f'<nav class="pn" aria-label="{t("التنقل بين المشاريع", "Project navigation")}">' + (f'<a href="../{prv["slug"]}/"><span>{t("السابق", "Previous")}</span><b>{E(prv["title"])}</b></a>' if prv else "<span></span>")
          + (f'<a class="nx" href="../{nxt["slug"]}/"><span>{t("التالي", "Next")}</span><b>{E(nxt["title"])}</b></a>' if nxt else "") + "</nav>")
    learn = "".join(f"<li>{E(x)}</li>" for x in g["learn"])
    hero = (f'<header class="ghero"><div class="ghero-in"><div class="ghero-t"><p class="crumb mono">{g["course"]} · {g["order"]:02d}</p><h1>{E(g["title"])}</h1>'
            f'<p class="lead">{E(g["summary"])}</p><ul class="learn">{learn}</ul>'
            + (f'<a class="rep" href="{PRE}reports/{g["slug"]}.pdf" download><span aria-hidden="true">↓</span> {t("تقرير المشروع", "Project report")} · PDF · {os.path.getsize(os.path.join(ROOT, "reports", g["slug"] + ".pdf")) // 1024} KB</a>' if os.path.exists(os.path.join(ROOT, "reports", g["slug"] + ".pdf")) else "")
            + '</div>'
            + (f'<div class="ghero-v">{topo_svg(g["topo"])}' + (f'<p class="cap">{E(g["ip_note"])}</p>' if g["ip_note"] else "") + '</div>' if g["topo"] else "") + '</div></header>')
    tocl = "".join(f'<li><a href="#{a}">{E(b)}</a></li>' for a, b in toc)
    other = t(f"{PRE}guides/{g['slug']}/", f"{PRE}ar/guides/{g['slug']}/")
    page = (head(f'{g["title"]} · Fahad Net Lab', g["summary"], 3 if LANG == "ar" else 2, other) + hero
            + f'<div class="docs">{sidebar(g["slug"])}<main id="main" class="doc">{"".join(sec)}{pn}</main><aside class="toc" aria-label="{t('في هذه الصفحة', 'On this page')}"><p>{t('في هذه الصفحة', 'On this page')}</p><ul>{tocl}</ul></aside></div>'
            + FOOT.replace("{pre}", PRE).replace("{me}", t("فهد عواد", "Fahad Awad")).replace("{uni}", t("جامعة الملك سعود", "King Saud University")))
    d = os.path.join(OUT(), "guides", g["slug"]); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "index.html"), "w").write(page)

PRE = "../../"
if __name__ == "__main__":
    for LANG in ("en", "ar"):
        for g in C().GUIDES:
            guide_page(g)
        print("built", LANG)
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
