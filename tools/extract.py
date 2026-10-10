"""Extract per-frame facts from a capture into JSON. Values come only from the capture."""
import json, sys
from scapy.all import rdpcap, Ether, Dot1Q, ARP, IP, TCP, UDP, ICMP, Raw

def frame(i, p):
    d = {"no": i, "t": round(float(p.time), 6), "len": len(p), "hex": bytes(p).hex()}
    if Ether in p: d.update(src_mac=p[Ether].src, dst_mac=p[Ether].dst, ethertype=hex(p[Ether].type))
    if Dot1Q in p: d.update(vlan=p[Dot1Q].vlan, pcp=p[Dot1Q].prio)
    if ARP in p: a=p[ARP]; d.update(proto="ARP", op=a.op, psrc=a.psrc, pdst=a.pdst, hwsrc=a.hwsrc, hwdst=a.hwdst)
    if IP in p: d.update(src=p[IP].src, dst=p[IP].dst, ttl=p[IP].ttl, ip_id=p[IP].id, ip_chksum=hex(p[IP].chksum))
    if ICMP in p: c=p[ICMP]; d.update(proto="ICMP", icmp_type=c.type, code=c.code, icmp_id=getattr(c,'id',None), icmp_seq=getattr(c,'seq',None), icmp_chksum=hex(c.chksum))
    if TCP in p:
        t=p[TCP]; pl=bytes(t.payload)
        d.update(proto="TCP", sport=t.sport, dport=t.dport, seq=t.seq, ack=t.ack, flags=str(t.flags), win=t.window, tcp_chksum=hex(t.chksum), plen=len(pl), payload_hex=pl.hex(), payload_txt=pl.decode('latin-1'))
    elif UDP in p: d.update(proto="UDP", sport=p[UDP].sport, dport=p[UDP].dport)
    return d

pk = rdpcap(sys.argv[1])
out = [frame(i+1, p) for i, p in enumerate(pk)]
json.dump(out, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
print(sys.argv[1], len(out), "frames")
