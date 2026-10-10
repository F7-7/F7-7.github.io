"""Field-level dissection of captured frames, with byte offsets.

Everything shown on the site about a frame comes from here, read straight from
the capture bytes. Nothing is typed in by hand.
"""
import struct
from scapy.all import rdpcap

ETYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x8100: "802.1Q", 0x86DD: "IPv6", 0x9000: "Loopback"}
IPPROTO = {1: "ICMP", 6: "TCP", 17: "UDP"}


def F(name, off, ln, value, note=""):
    return {"name": name, "off": off, "len": ln, "value": value, "note": note}


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


def ip4(b):
    return ".".join(str(x) for x in b)


def tcp_flags(v):
    names = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
    return " ".join(n for bit, n in names if v & bit) or "-"


def dissect(raw):
    """Return (layers, summary). Each layer: {name, off, len, fields[]}."""
    layers, s = [], {}
    b = raw
    if len(b) < 14:
        return layers, s
    et = struct.unpack("!H", b[12:14])[0]
    eth = {"name": "Ethernet II" if et >= 0x600 else "IEEE 802.3", "off": 0, "len": 14, "fields": [
        F("Destination MAC", 0, 6, mac(b[0:6])),
        F("Source MAC", 6, 6, mac(b[6:12])),
    ]}
    s.update(dst_mac=mac(b[0:6]), src_mac=mac(b[6:12]))
    off = 12
    if et == 0x8100:
        tci = struct.unpack("!H", b[14:16])[0]
        eth["fields"].append(F("TPID", 12, 2, "0x8100", "802.1Q tag"))
        layers.append(eth)
        vid, pcp, dei = tci & 0x0FFF, tci >> 13, (tci >> 12) & 1
        layers.append({"name": "802.1Q VLAN tag", "off": 12, "len": 4, "fields": [
            F("TPID", 12, 2, "0x8100"),
            F("PCP · DEI · VID", 14, 2, f"PCP={pcp} · DEI={dei} · VID={vid}", f"TCI=0x{tci:04x}"),
        ]})
        s["vlan"] = vid
        off = 16
        et = struct.unpack("!H", b[16:18])[0]
        layers[-2]["len"] = 18
    else:
        layers.append(eth)
    if et < 0x600:  # 802.3 length field -> LLC
        layers[0]["fields"].append(F("Length", off, 2, str(et)))
        d = b[0:6]
        kind = {"01:80:c2:00:00:00": "STP BPDU (IEEE)", "01:00:0c:cc:cc:cd": "PVST+ BPDU (Cisco)",
                "01:00:0c:cc:cc:cc": "CDP / VTP / DTP (Cisco)"}.get(mac(d), "LLC")
        layers.append({"name": kind, "off": off + 2, "len": len(b) - off - 2, "fields": [
            F("DSAP · SSAP · Control", off + 2, 3, f"0x{b[off+2]:02x} · 0x{b[off+3]:02x} · 0x{b[off+4]:02x}")]})
        s.update(proto=kind.split(" ")[0], info=kind)
        return layers, s
    layers[-1]["fields"].append(F("EtherType", off, 2, f"0x{et:04x}", ETYPES.get(et, "")))
    p = off + 2
    s["ethertype"] = ETYPES.get(et, hex(et))
    if et == 0x0806:
        op = struct.unpack("!H", b[p+6:p+8])[0]
        f = [F("Hardware type", p, 2, f"0x{struct.unpack('!H', b[p:p+2])[0]:04x}", "Ethernet"),
             F("Protocol type", p+2, 2, f"0x{struct.unpack('!H', b[p+2:p+4])[0]:04x}", "IPv4"),
             F("HW size · Proto size", p+4, 2, f"{b[p+4]} · {b[p+5]}"),
             F("Opcode", p+6, 2, str(op), "Request" if op == 1 else "Reply"),
             F("Sender MAC", p+8, 6, mac(b[p+8:p+14])),
             F("Sender IP", p+14, 4, ip4(b[p+14:p+18])),
             F("Target MAC", p+18, 6, mac(b[p+18:p+24])),
             F("Target IP", p+24, 4, ip4(b[p+24:p+28]))]
        layers.append({"name": "ARP", "off": p, "len": 28, "fields": f})
        if len(b) > p + 28:
            layers.append({"name": "Padding", "off": p+28, "len": len(b)-p-28, "fields": [F("Padding", p+28, len(b)-p-28, f"{len(b)-p-28} bytes")]})
        s.update(proto="ARP", src=ip4(b[p+14:p+18]), dst=ip4(b[p+24:p+28]),
                 info=(f"Who has {ip4(b[p+24:p+28])}? Tell {ip4(b[p+14:p+18])}" if op == 1 else f"{ip4(b[p+14:p+18])} is at {mac(b[p+8:p+14])}"))
        return layers, s
    if et != 0x0800:
        s.update(proto=ETYPES.get(et, hex(et)), info="")
        return layers, s
    ihl = (b[p] & 0x0F) * 4
    tot = struct.unpack("!H", b[p+2:p+4])[0]
    tot_note = ""
    if tot == 0 or tot > len(b) - p:
        tot_note = "0 في الالتقاط: كرت الشبكة يعبّيها بعدين (TCP Segmentation Offload)" if tot == 0 else "أكبر من الإطار"
        s["tso"] = tot == 0
        tot = len(b) - p
    proto = b[p+9]
    f = [F("Version · IHL", p, 1, f"4 · {ihl} bytes"),
         F("DSCP · ECN", p+1, 1, f"0x{b[p+1]:02x}"),
         F("Total length", p+2, 2, str(struct.unpack("!H", b[p+2:p+4])[0]), tot_note),
         F("Identification", p+4, 2, f"0x{struct.unpack('!H', b[p+4:p+6])[0]:04x}"),
         F("Flags · Fragment offset", p+6, 2, f"0x{struct.unpack('!H', b[p+6:p+8])[0]:04x}"),
         F("TTL", p+8, 1, str(b[p+8])),
         F("Protocol", p+9, 1, f"{proto}", IPPROTO.get(proto, "")),
         F("Header checksum", p+10, 2, f"0x{struct.unpack('!H', b[p+10:p+12])[0]:04x}"),
         F("Source IP", p+12, 4, ip4(b[p+12:p+16])),
         F("Destination IP", p+16, 4, ip4(b[p+16:p+20]))]
    layers.append({"name": "IPv4", "off": p, "len": ihl, "fields": f})
    s.update(src=ip4(b[p+12:p+16]), dst=ip4(b[p+16:p+20]), ttl=b[p+8])
    q = p + ihl
    end = p + tot  # ignore Ethernet padding
    if proto == 6:
        sp, dp, seq, ack = struct.unpack("!HHII", b[q:q+12])
        hl = (b[q+12] >> 4) * 4
        fl = b[q+13]
        win = struct.unpack("!H", b[q+14:q+16])[0]
        ck = struct.unpack("!H", b[q+16:q+18])[0]
        plen = end - q - hl
        f = [F("Source port", q, 2, str(sp)), F("Destination port", q+2, 2, str(dp)),
             F("Sequence number", q+4, 4, str(seq)), F("Acknowledgment number", q+8, 4, str(ack)),
             F("Header length · Flags", q+12, 2, f"{hl} bytes · {tcp_flags(fl)}"),
             F("Window", q+14, 2, str(win)), F("Checksum", q+16, 2, f"0x{ck:04x}"),
             F("Urgent pointer", q+18, 2, str(struct.unpack('!H', b[q+18:q+20])[0]))]
        if hl > 20:
            f.append(F("Options", q+20, hl-20, f"{hl-20} bytes"))
        layers.append({"name": "TCP", "off": q, "len": hl, "fields": f})
        pl = b[q+hl:end]
        if plen > 0:
            txt = pl.decode("latin-1")
            layers.append({"name": "Payload", "off": q+hl, "len": plen, "fields": [F("Data", q+hl, plen, f"{plen} bytes")]})
            s["payload_txt"] = txt
        s.update(proto="TCP", sport=sp, dport=dp, seq=seq, ack=ack, flags=tcp_flags(fl), win=win, plen=plen)
        first = (s.get("payload_txt") or "").split("\r\n")[0][:70]
        s["info"] = f"{sp} → {dp} [{tcp_flags(fl)}] Seq={seq} Ack={ack} Len={plen}" + (f"  ·  {first}" if first else "")
    elif proto == 1:
        t, c = b[q], b[q+1]
        ck, iid, isq = struct.unpack("!HHH", b[q+2:q+8])
        dlen = end - q - 8
        f = [F("Type", q, 1, str(t), {8: "Echo request", 0: "Echo reply"}.get(t, "")), F("Code", q+1, 1, str(c)),
             F("Checksum", q+2, 2, f"0x{ck:04x}"), F("Identifier", q+4, 2, str(iid)), F("Sequence", q+6, 2, str(isq))]
        layers.append({"name": "ICMP", "off": q, "len": 8, "fields": f})
        if dlen > 0:
            layers.append({"name": "ICMP data", "off": q+8, "len": dlen, "fields": [F("Data", q+8, dlen, b[q+8:end].decode('latin-1'))]})
        s.update(proto="ICMP", icmp_type=t, icmp_id=iid, icmp_seq=isq, icmp_ck=f"0x{ck:04x}", icmp_dlen=dlen,
                 info=f"{'Echo request' if t == 8 else 'Echo reply' if t == 0 else 'type '+str(t)} id={iid} seq={isq} ttl={b[p+8]}")
    elif proto == 17:
        sp, dp, ul = struct.unpack("!HHH", b[q:q+6])
        layers.append({"name": "UDP", "off": q, "len": 8, "fields": [F("Source port", q, 2, str(sp)), F("Destination port", q+2, 2, str(dp)), F("Length", q+4, 2, str(ul))]})
        s.update(proto="UDP", sport=sp, dport=dp, info=f"UDP {sp} → {dp}")
    if end < len(b):
        layers.append({"name": "Ethernet padding", "off": end, "len": len(b)-end, "fields": [F("Padding", end, len(b)-end, f"{len(b)-end} bytes")]})
    return layers, s


def load(path):
    out = []
    for i, p in enumerate(rdpcap(path)):
        raw = bytes(p)
        layers, s = dissect(raw)
        s.update(no=i+1, t=float(p.time), length=len(raw))
        out.append({"s": s, "layers": layers, "hex": raw.hex()})
    t0 = out[0]["s"]["t"] if out else 0
    for o in out:
        o["s"]["rt"] = round(o["s"]["t"] - t0, 6)
        del o["s"]["t"]
    return out


def tcp_checks(frames):
    """Walk every TCP stream and test: next Seq from a side == previous Seq + Len (+1 for SYN/FIN),
    and every Ack equals the next byte the other side is expected to send. Returns rows for the site."""
    rows, nxt = [], {}
    for fr in frames:
        s = fr["s"]
        if s.get("proto") != "TCP":
            continue
        key = (s["src"], s["sport"], s["dst"], s["dport"])
        rev = (s["dst"], s["dport"], s["src"], s["sport"])
        fl = s["flags"].split()
        expect = nxt.get(key)
        status, note = "ok", ""
        if expect is not None and s["seq"] != expect:
            if s["seq"] < expect and s["plen"] > 0:
                status, note = "retx", "إعادة إرسال: نفس البايتات انرسلت مرة ثانية"
            elif s["seq"] < expect:
                status, note = "keep", "ACK بدون بيانات جديدة"
            else:
                status, note = "gap", f"المتوقع {expect}"
        adv = s["plen"] + (1 if "SYN" in fl else 0) + (1 if "FIN" in fl else 0)
        if expect is None or s["seq"] + adv > expect:
            nxt[key] = s["seq"] + adv
        ack_ok = None
        if "ACK" in fl and rev in nxt:
            ack_ok = "exact" if s["ack"] == nxt[rev] else ("partial" if s["ack"] < nxt[rev] else "beyond")
        rows.append({"no": s["no"], "dir": f"{s['src']}:{s['sport']} → {s['dst']}:{s['dport']}", "flags": s["flags"],
                     "seq": s["seq"], "ack": s["ack"], "len": s["plen"], "next": s["seq"] + adv,
                     "seq_status": status, "ack_ok": ack_ok, "note": note})
    return rows
