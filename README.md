# Fahad Net Lab

منصة مشاريع الشبكات لفهد عواد (COS 370 · COS 372، جامعة الملك سعود).
الموقع: https://f7-7.github.io · المدونة: https://fahadnetlab.wordpress.com

## كيف تُبنى الصفحات

كل رقم في الأدلة (Seq و Ack و Hex و TTL والأطوال) يُقرأ من ملفات `captures/*.pcapng` عند البناء، ولا يُكتب باليد.

```bash
pip install scapy
python3 -I tools/build.py        # الأدلة في guides/ + tools/story.json
python3 -I tools/build_index.py  # الصفحة الرئيسية
```

| الملف | الدور |
|---|---|
| `tools/decode.py` | تفكيك الإطارات إلى حقول مع مواقع البايتات، والتحقق الآلي من Seq و Ack |
| `tools/content.py` | نصوص الأدلة والروابط الرسمية والمراجع |
| `tools/build.py` | يولّد صفحات الأدلة والنتائج من الالتقاطات |
| `tools/build_index.py` | الصفحة الرئيسية وقصة بناء الشبكة |

## الناقص
- ملف التقاط Telnet: الدليل يعرض قيم التقرير موسومة بأنها غير متحقق منها.
- إعدادات الراوتر والسويتشات الفعلية من GNS3: الدليل يعرض أوامر قياسية موسومة كمثال.
