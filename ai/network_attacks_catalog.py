"""
NetPacket Inspector - Network Attacks Encyclopedia & Forensic Dissector
Detailed reference of network attack vectors, packet mechanics, MITRE ATT&CK mappings, and automated packet matching.
"""

from typing import List, Dict, Any
from core.pcap_parser import ParsedPacket
from intel.threat_detector import ThreatDetector, ThreatAlert


class NetworkAttackDefinition:
    """Represents a standard network attack type with educational descriptions and packet matching."""

    def __init__(
        self,
        attack_id: str,
        name_en: str,
        name_ar: str,
        category: str,
        severity: str,
        mitre_id: str,
        mitre_tactic: str,
        mechanism_explanation: str,
        detection_rules: str,
        mitigation: str
    ):
        self.attack_id = attack_id
        self.name_en = name_en
        self.name_ar = name_ar
        self.category = category
        self.severity = severity
        self.mitre_id = mitre_id
        self.mitre_tactic = mitre_tactic
        self.mechanism_explanation = mechanism_explanation
        self.detection_rules = detection_rules
        self.mitigation = mitigation


# Global Knowledge Base of Network Attacks
ATTACKS_CATALOG: List[NetworkAttackDefinition] = [
    NetworkAttackDefinition(
        attack_id="ATK-DNS-EXFIL",
        name_en="DNS Tunneling & Covert Data Exfiltration",
        name_ar="تسريب البيانات عبر أنفاق DNS واستعلامات النطاقات الفرعية",
        category="Exfiltration & C2",
        severity="CRITICAL",
        mitre_id="T1048.003 / T1071.004",
        mitre_tactic="Exfiltration / Command and Control",
        mechanism_explanation=(
            "يقوم المهاجم بتشفير أو ضغط البيانات الحساسة (مثل كلمات المرور، أو مستندات سرية) داخل نصوص Base64 أو Hex "
            "وجعلها كنطاقات فرعية (Subdomains) في استعلامات DNS (Port 53 UDP). تصل الاستعلامات إلى خادم الأسماء التابع للمهاجم، "
            "والذي يقوم بفك النصوص وإعادة تجميع الملفات المسربة متجاوزاً الجدران النارية التي تسمح بمرور حركة الـ DNS عادة."
        ),
        detection_rules=(
            "1. استعلامات DNS تحتوي على نطاقات فرعية يزيد طولها عن 25-45 حرفاً.\n"
            "2. ارتفاع درجة الإنتروبيا (Shannon Entropy > 3.4) في أسماء النطاقات المستعلم عنها.\n"
            "3. وجود نصوص Base64 صريحة قابلة للفك داخل أسماء الـ Subdomains."
        ),
        mitigation="تطبيق حلول DNS Sinkholing، وتفتيش حركة DNS عبر DNS Inspection، وحظر الاستعلام المباشر لخوادم DNS الخارجية غير الموثوقة."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-ARP-SPOOF",
        name_en="ARP Spoofing / Poisoning & Man-in-the-Middle (MitM)",
        name_ar="تسميم جدول ARP وانتحال البوابة واعتراض الاتصالات",
        category="Credential Access & MitM",
        severity="CRITICAL",
        mitre_id="T1557.002",
        mitre_tactic="Credential Access / Collection",
        mechanism_explanation=(
            "يقوم المهاجم بإرسال حزم ARP Reply وهمية وغير مطلوبة (Gratuitous ARP) إلى أجهزة الضحايا والبوابة الافتراضية، "
            "معلناً أن عنوان IP الخاص بالبوابة (Gateway) مقترن بعنوان الـ MAC الخاص بجهاز المهاجم. "
            "مما يدفع حركة البيانات للمرور عبر المهاجم أولاً قبل وصولها للوجهة الحقيقية للتجسس والتعديل عليها."
        ),
        detection_rules=(
            "1. ظهور حزم ARP Reply لنفس عنوان الـ IP صادرة من عنواني MAC مختلفين.\n"
            "2. تدفق حزم ARP غير مطلوبة بمعدل سريع لتسميم الذاكرة المؤقتة (ARP Cache)."
        ),
        mitigation="تفعيل Dynamic ARP Inspection (DAI) على المحولات (Switches)، وربط المنافذ بـ DHCP Snooping وعناوين MAC الثابتة."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-SYN-SCAN",
        name_en="TCP SYN Port Scan (Half-Open Reconnaissance)",
        name_ar="مسح المنافذ الاستطلاعي نصف المفتوح (TCP SYN Scan)",
        category="Discovery",
        severity="HIGH",
        mitre_id="T1046",
        mitre_tactic="Discovery",
        mechanism_explanation=(
            "يقوم المهاجم بإرسال حزمة TCP مع تفعيل الـ SYN Flag فقط لمجموعة من المنافذ المستهدفة. "
            "إذا رد المنفذ بـ SYN+ACK، فهذا يعني أن المنفذ مفتوح؛ وحينها يرسل المهاجم RST بدلاً من ACK لقطع الاتصال دون تسجيل جلسة كاملة. "
            "أما إذا رد المنفذ بـ RST، فالمنفذ مغلق."
        ),
        detection_rules=(
            "1. إرسال عدد كبير من حزم TCP SYN من مصدر واحد لمنافذ وجهة متعددة دون إتمام المصافحة الثلاثية (3-Way Handshake).\n"
            "2. انعدام تبادل البيانات بعد فتح الاتصال."
        ),
        mitigation="استخدام جدران نارية تكشف مسح المنافذ (Stateful Firewalls / IDS)، وتحديد معدل الاتصالات (Rate Limiting)."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-STEALTH-SCAN",
        name_en="TCP Stealth Scans (FIN, NULL, Xmas Tree Scans)",
        name_ar="المسح الشبكي المتخفي (FIN / NULL / Xmas)",
        category="Defense Evasion",
        severity="HIGH",
        mitre_id="T1046 / T1562",
        mitre_tactic="Discovery / Defense Evasion",
        mechanism_explanation=(
            "يعتمد على استغلال كيفية تعامل نظام TCP (RFC 793) مع الحزم الشاذة لتجاوز جدران الحماية غير الذكية:\n"
            "- NULL Scan: إرسال حزمة بدون أي أعلام (Flags = 0).\n"
            "- FIN Scan: إرسال حزمة بعلم FIN فقط دون وجود اتصال مفتوح مسبقاً.\n"
            "- Xmas Scan: تفعيل أعلام FIN و PSH و URG معاً كشجرة مضيئة."
        ),
        detection_rules=(
            "1. حزم TCP لا تحمل أعلاماً (NULL Flags).\n"
            "2. حزم تحمل توليفات أعلام محظورة في المعايير مثل (FIN+PSH+URG أو FIN بدون ACK/SYN)."
        ),
        mitigation="تطبيق جدران نارية حديثة تفحص حالة الاتصال (Stateful Packet Inspection) وتسقط الحزم الشاذة تلقائياً."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-CLEARTEXT-LEAK",
        name_en="Cleartext Credential Leak & Unencrypted Sniffing",
        name_ar="تسريب واعتراض بيانات الاعتماد وكلمات المرور غير المشفرة",
        category="Credential Access",
        severity="HIGH",
        mitre_id="T1040 / T1552",
        mitre_tactic="Credential Access",
        mechanism_explanation=(
            "إرسال كلمات المرور، أسماء المستخدمين، أو جلسات المصادقة عبر بروتوكولات غير مشفرة (مثل HTTP, FTP, Telnet). "
            "يمكن لأي متصنت أو مهاجم ينفذ هجوم MitM قراءة هذه البيانات فوراً واستخراج حسابات الإدارة."
        ),
        detection_rules=(
            "1. ترويسات HTTP Authorization: Basic <base64>.\n"
            "2. طلبات HTTP POST تحتوي على حقول password= أو user= أو admin=.\n"
            "3. أوامر بروتوكول FTP مثل USER و PASS بنص صريح."
        ),
        mitigation="إلزام التشفير الكامل عبر HTTPS (TLS 1.3)، وتعطيل البروتوكولات القديمة مثل HTTP و FTP و Telnet واستبدالها بـ SSH و SFTP."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-C2-BACKDOOR",
        name_en="Backdoor / Reverse Shell & C2 Channel",
        name_ar="الاتصال بقنوات التحكم الخبيثة وأبواب الاختراق الخلفية (C2)",
        category="Command and Control",
        severity="CRITICAL",
        mitre_id="T1571 / T1059",
        mitre_tactic="Command and Control / Execution",
        mechanism_explanation=(
            "يقوم برنامج خبيث تم تشغيله على الضحية بفتح اتصال خارجي (Reverse Shell) إلى سيرفر المهاجم على منافذ غير قياسية "
            "(مثل منفذ 4444، 1337، 31337) لإعطاء المهاجم وصولاً طرفياً لتنفيذ أوامر PowerShell أو Bash والتحكم بالنظام."
        ),
        detection_rules=(
            "1. اتصالات صادرة نحو منافذ مشبوهة شائعة في أدوات الاختراق (4444, 1337, 5555, 6667).\n"
            "2. حزم تحتوي على نصوص تشغيل موجه الأوامر (cmd.exe, powershell.exe, /bin/sh, downloadstring)."
        ),
        mitigation="حظر الاتصالات الصادرة (Outbound Traffic Filtering) للمنافذ غير المصرح بها، واستخدام برامج EDR لمراقبة العمليات."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-ICMP-SWEEP",
        name_en="ICMP Echo Ping Sweep & Host Discovery",
        name_ar="مسح عناوين الشبكة لاكتشاف الأجهزة الحية (Ping Sweep)",
        category="Discovery",
        severity="MEDIUM",
        mitre_id="T1018",
        mitre_tactic="Discovery",
        mechanism_explanation=(
            "إرسال حزم ICMP Echo Request متتالية إلى نطاق عناوين IP كامل (Subnet) لمعرفة الأجهزة المتصلة والحية "
            "بناءً على استقبال ردود ICMP Echo Reply، مما يمهد لاستهدافها."
        ),
        detection_rules=(
            "إرسال متتالي لحزم ICMP Echo Request من نفس المصدر إلى عدد كبير من عناوين الوجهات المختلفة في فترة وجيزة."
        ),
        mitigation="تعطيل الاستجابة لـ ICMP Echo على جدران حماية الأجهزة الطرفية غير المطلوبة."
    ),
    NetworkAttackDefinition(
        attack_id="ATK-SYN-FLOOD",
        name_en="TCP SYN Flood Denial of Service (DoS)",
        name_ar="هجوم إغراق الشبكة وحجب الخدمة بحزم SYN",
        category="Impact",
        severity="HIGH",
        mitre_id="T1498",
        mitre_tactic="Impact",
        mechanism_explanation=(
            "إغراق خادم الهدف بآلاف حزم TCP SYN مع عناوين مصدر مزورة أو دون إكمال الاتصال، "
            "مما يؤدي لاستنزاف جدول الاتصالات المؤقتة (SYN Backlog Queue) في نظام التشغيل ويمنع المستخدمين الشرعيين من الاتصال."
        ),
        detection_rules=(
            "معدل هائل من حزم TCP SYN نحو سيرفر معين دون إتمام مصافحة أو مع انعدام حزم ACK المقابلة."
        ),
        mitigation="تفعيل تقنية SYN Cookies، وتقييد معدل الاتصالات (SYN Rate Limiting)، واستخدام حلول حماية DDoS."
    )
]


class AttackInspectorEngine:
    """Matches catalog attacks against actual parsed packet stream."""

    @staticmethod
    def match_loaded_packets(packets: List[ParsedPacket], alerts: List[ThreatAlert]) -> List[Dict[str, Any]]:
        """Cross-references detected alerts and packet indicators with the attack catalog."""
        results = []

        # Map alert rule types to attack IDs
        alert_map = {
            "NIDS-EXFIL-001": "ATK-DNS-EXFIL",
            "NIDS-MITM-001": "ATK-ARP-SPOOF",
            "NIDS-SCAN-001": "ATK-SYN-SCAN",
            "NIDS-SCAN-002": "ATK-STEALTH-SCAN",
            "NIDS-CRED-001": "ATK-CLEARTEXT-LEAK",
            "NIDS-C2-001": "ATK-C2-BACKDOOR",
            "NIDS-DISC-001": "ATK-ICMP-SWEEP",
            "NIDS-DOS-001": "ATK-SYN-FLOOD"
        }

        alerts_by_atk_id = {}
        for a in alerts:
            atk_id = alert_map.get(a.rule_id)
            if atk_id:
                alerts_by_atk_id[atk_id] = a

        for atk in ATTACKS_CATALOG:
            alert_match = alerts_by_atk_id.get(atk.attack_id)
            is_detected = alert_match is not None
            matched_pkts = alert_match.related_packet_nums if alert_match else []
            evidence = alert_match.evidence if alert_match else {}

            results.append({
                "Definition": atk,
                "Is_Detected": is_detected,
                "Status": "🚨 DETECTED IN THIS CAPTURE" if is_detected else "✅ No Matching Traffic Detected",
                "Matched_Packets_Count": len(matched_pkts),
                "Matched_Packet_Numbers": matched_pkts,
                "Evidence": evidence,
                "Alert_Instance": alert_match
            })

        # Sort so detected attacks appear on top
        results.sort(key=lambda r: (not r["Is_Detected"], r["Definition"].severity != "CRITICAL", r["Definition"].severity != "HIGH"))
        return results
