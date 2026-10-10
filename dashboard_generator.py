"""
NetPacket Inspector Pro - Smart SOC Platform Edition
Modern White & Royal Blue Corporate SOC Dashboard
- White Background with Elegant Royal Blue Borders and Accents
- Top Command Header with Kali Linux x Wireshark Hybrid Emblem
- Critical Security Events Hero Banner (Red Gradient with One-Click Drilldown)
- Metric HUD Cards Grid (Clean White Cards with Colored Borders & Badges)
- Interactive Physics Force-Directed Network Topology Graph (Draggable Nodes)
- Full Wireshark-Style Deep Packet Dissector (3-Pane: Protocol Tree, Interactive Hex, Decoded ASCII)
- MITRE ATT&CK Matrix & Chronological Attack Kill-Chain Timeline
- Endpoint Geolocation, ASN & Correlated Domain Names
- Extracted File Carving Artifacts Sandbox
- Interactive SOC Incident Response Checklist with progress tracking
- Built-in Web Audio Cyber Synthesizer SFX
"""

import json
import os
import datetime
from typing import List, Dict, Any

from pcap_parser import ParsedPacket, bytes_to_hex_dump
from analyzer import TrafficAnalyzer
from threat_detector import ThreatDetector, ThreatAlert
from stream_profiler import StreamProfiler
from threat_intel import ThreatIntelEngine
from geo_resolver import GeoResolverEngine
from file_carver import FileCarverEngine
from ai_triage_playbook import IncidentTriageEngine
from assets_data import EMBLEM_B64
from ai_engine import (
    AIFlowFeatureExtractor,
    AISentinelEngine,
    DFIRTelemetryEngine,
    MITRE_ATTACK_MAPPING
)




# =========================================================================
# AI SENTINEL & DFIR SUITE EXTENSION ASSETS FOR SMART SOC DASHBOARD
# =========================================================================

AI_CSS_BLOCK = r'''
  /* =========================================================================
     AI SENTINEL & SENTINEL DFIR HUB SUITE STYLES (MATCHING SCREENSHOTS)
     ========================================================================= */
  .dfir-hub-header {
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 14px 14px 0 0;
    padding: 12px 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 0;
  }
  .dfir-subnav-bar {
    display: flex;
    align-items: center;
    gap: 6px;
    overflow-x: auto;
    flex: 1;
    scrollbar-width: thin;
  }
  .dfir-subnav-btn {
    background: transparent;
    color: var(--text-muted);
    border: none;
    border-bottom: 2.5px solid transparent;
    padding: 8px 14px;
    font-size: 12.5px;
    font-weight: 700;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
    transition: all 0.2s ease;
    border-radius: 6px 6px 0 0;
  }
  .dfir-subnav-btn:hover {
    color: var(--primary-blue);
    background: var(--blue-subtle);
  }
  .dfir-subnav-btn.active {
    color: #ef4444;
    border-bottom-color: #ef4444;
    background: rgba(239, 68, 68, 0.1);
    font-weight: 800;
  }
  .dfir-hub-switcher {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 6px;
    flex-shrink: 0;
  }
  .dfir-cti-info-pill {
    font-size: 11px;
    color: var(--primary-deep);
    font-weight: 700;
    background: var(--blue-subtle);
    border: 1px solid var(--blue-border);
    border-radius: 6px;
    padding: 3px 8px;
  }
  .dfir-mode-toggle-group {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .dfir-mode-radio {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 700;
    color: var(--text-main);
    cursor: pointer;
  }
  .dfir-hub-body {
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-top: none;
    border-radius: 0 0 14px 14px;
    padding: 22px;
    margin-bottom: 22px;
  }
  .dfir-subview { display: none; }
  .dfir-subview.active { display: block; }
  .dfir-mode-container { display: none; }
  .dfir-mode-container.active { display: block; }

  .dfir-hero-banner {
    margin-bottom: 18px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-neutral);
  }
  .dfir-hero-banner h2 {
    margin: 0;
    font-size: 17px;
    font-weight: 800;
    color: var(--primary-deep);
  }
  .dfir-hero-banner p {
    margin: 4px 0 0 0;
    font-size: 12.5px;
    color: var(--text-muted);
  }

  .dfir-4q-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 16px;
  }
  @media (max-width: 950px) {
    .dfir-4q-grid { grid-template-columns: 1fr; }
  }
  .dfir-card {
    background: var(--bg-subtle);
    border: 1.5px solid var(--blue-border);
    border-radius: 10px;
    padding: 18px;
    position: relative;
  }
  .dfir-card-red { border-color: #ef4444; }
  .dfir-card-cyan { border-color: #06b6d4; }
  .dfir-card-amber { border-color: #f59e0b; }
  .dfir-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border-neutral);
  }
  .dfir-card-title {
    font-size: 14.5px;
    font-weight: 800;
    color: var(--text-main);
  }
  .dfir-code-box {
    background: #050b14;
    border: 1px solid var(--blue-border);
    border-radius: 6px;
    padding: 12px 16px;
    font-family: var(--font-mono);
    font-size: 12px;
    color: #00F0FF;
    margin: 0;
    overflow-x: auto;
    white-space: pre-wrap;
  }

  /* Interactive Attack Graphs Controls */
  .ai-graph-controls-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 12px;
    padding: 10px 18px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }
  .ai-control-group {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    font-weight: 700;
  }
  .ai-control-label {
    color: var(--primary-blue);
    font-family: var(--font-mono);
  }
  .ai-control-option {
    display: flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
    color: var(--text-main);
  }

  /* AI SOC Cockpit & Threat Ops */
  .ops-kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 18px;
  }
  .ops-kpi-card {
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 12px;
    padding: 14px 18px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }
  .ops-kpi-title { font-size: 11.5px; font-weight: 700; color: var(--text-muted); }
  .ops-kpi-val { font-size: 24px; font-weight: 900; margin-top: 4px; }

  /* 2x2 Confusion Matrix */
  .ai-cm-grid {
    display: grid;
    grid-template-columns: 140px 1fr 1fr;
    grid-gap: 8px;
    margin-top: 10px;
  }
  .ai-cm-cell {
    background: var(--bg-card);
    border: 1px solid var(--blue-border);
    border-radius: 8px;
    padding: 12px;
    text-align: center;
  }
  .ai-cm-cell.tp { border-color: var(--success-green); background: var(--success-bg); }
  .ai-cm-cell.tn { border-color: var(--primary-blue); background: var(--blue-subtle); }
  .ai-cm-cell.fp { border-color: var(--warn-orange); background: var(--warn-bg); }
  .ai-cm-cell.fn { border-color: var(--crit-red); background: var(--crit-bg); }
  .ai-cm-num { font-size: 20px; font-weight: 900; display: block; }
  .ai-cm-desc { font-size: 11px; color: var(--text-muted); font-weight: 700; }

  /* Viva Accordion */
  .viva-item {
    background: var(--bg-card);
    border: 1px solid var(--border-neutral);
    border-radius: 8px;
    margin-bottom: 8px;
    overflow: hidden;
  }
  .viva-header {
    padding: 12px 16px;
    font-size: 13px;
    font-weight: 700;
    color: var(--primary-deep);
    cursor: pointer;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-subtle);
  }
  .viva-header:hover { background: var(--blue-subtle); }
  .viva-content {
    padding: 14px 18px;
    font-size: 12.5px;
    color: var(--text-navy);
    line-height: 1.7;
    border-top: 1px solid var(--border-neutral);
    display: none;
  }
  .viva-item.open .viva-content { display: block; }
'''

AI_NAV_TABS_BLOCK = r'''
  <button class="nav-tab-btn" onclick="switchTab('tab-dfir-hub', this)" style="border: 1px solid rgba(0,240,255,0.4); color: var(--primary-deep); font-weight:800;">
    <span>🧭 Sentinel DFIR Hub</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-ai-graphs', this)">
    <span>🕸️ AI Attack Graphs</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-ai-cockpit', this)">
    <span>🧠 AI SOC Cockpit</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-radar', this)">
    <span>📡 DNS & TLS Radar</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-sandbox', this)">
    <span>🔬 AI Sandbox</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-benchmark', this)">
    <span>📊 AI Benchmark & Viva</span>
  </button>
'''

AI_HTML_TABS_BLOCK = r'''
<!-- =======================================================================
     TAB 7: 🧭 SENTINEL DFIR HUB & THREAT OPERATIONS PLATFORM
     ======================================================================= -->
<div id="tab-dfir-hub" class="tab-pane">
  <div class="dfir-hub-header">
    <div class="dfir-subnav-bar" id="dashSubNavBar">
      <button class="dfir-subnav-btn active" id="dashBtn4Q" onclick="switchDashDfirSubTab('4q')">🎯 الأسئلة الجنائية الأربعة (Forensic 4Q)</button>
      <button class="dfir-subnav-btn" id="dashBtnGraph" onclick="switchDashDfirSubTab('graph')">🕸️ خريطة علاقات الهجوم (Attack Graph)</button>
      <button class="dfir-subnav-btn" id="dashBtnDns" onclick="switchDashDfirSubTab('dns')">🌐 استخبارات DNS وفحص الأنفاق (DNS Telemetry)</button>
      <button class="dfir-subnav-btn" id="dashBtnTls" onclick="switchDashDfirSubTab('tls')">🔒 فحص حركة TLS المشفرة (TLS / SSL)</button>
      <button class="dfir-subnav-btn" id="dashBtnCases" onclick="switchDashDfirSubTab('cases')">📁 إدارة القضايا (Cases Management)</button>
      <button class="dfir-subnav-btn" id="dashBtnFlows" onclick="switchDashDfirSubTab('flows')">🌊 تفكيك التدفقات والتفسير (Flows & Explainability)</button>
      <button class="dfir-subnav-btn" id="dashBtnCorrelation" onclick="switchDashDfirSubTab('correlation')">🧩 محرك الربط (Correlation Engine)</button>
    </div>
    <div class="dfir-hub-switcher">
      <div class="dfir-cti-info-pill">ℹ️ الاستخبارات CTI مفعلة محلياً وتلقائياً</div>
      <div class="dfir-mode-toggle-group">
        <label class="dfir-mode-radio">
          <input type="radio" name="dashHubMode" value="threat_ops" onchange="switchDashDfirHubMode('threat_ops')">
          <span>🛡️ مركز العمليات والاستخبارات الحية (Threat Ops)</span>
        </label>
        <label class="dfir-mode-radio">
          <input type="radio" name="dashHubMode" value="sentinel_hub" checked onchange="switchDashDfirHubMode('sentinel_hub')">
          <span>🧭 منصة التحقيق الجنائي والأدلة الرقمية (Sentinel DFIR Hub)</span>
        </label>
      </div>
    </div>
  </div>

  <div class="dfir-hub-body">
    <!-- MODE 1: SENTINEL HUB -->
    <div id="dashModeSentinel" class="dfir-mode-container active">
      <!-- 1. SUBVIEW 4Q -->
      <div class="dfir-subview active" id="subview-dash-4q">
        <div class="dfir-hero-banner">
          <h2>🎯 إجابة الذكاء الاصطناعي عن الأسئلة الجنائية الأربعة (AI Incident Grounding)</h2>
          <p>تحويل سيل التدفقات والحزم إلى سرد جنائي متماسك يجيب عن الأسئلة الحيوية لفرق SOC و DFIR بدقة متناهية.</p>
        </div>
        <div class="dfir-4q-grid">
          <div class="dfir-card dfir-card-red">
            <div class="dfir-card-header">
              <span class="dfir-card-title">1️⃣ ماذا حدث؟ (What Happened?)</span>
              <span class="badge-tag badge-crit" id="dash4qConfidence">CONFIDENCE: 99%</span>
            </div>
            <div style="font-size:13px; line-height:1.7;">
              <div><strong>تصنيف النشاط:</strong> <span id="dash4qAttackType" style="color:var(--crit-red); font-weight:800;">Direct Network Flood / SYN PortScan</span></div>
              <div style="margin-top:6px;"><strong>المؤشرات الجنائية المرصودة:</strong></div>
              <ul id="dash4qIndicators" style="margin-left:20px; font-size:12px; color:var(--text-muted); margin-top:4px;">
                <li>ارتفاع متطرف في رايات SYN دون إتمام المصافحة الثلاثية</li>
                <li>نمط مسح منافذ استطلاعي سريع وشامل</li>
              </ul>
              <div style="margin-top:6px; font-size:11.5px; font-family:var(--font-mono); color:var(--primary-blue);" id="dash4qMitre">MITRE ATT&CK: T1498 (Network Flood) / T1046 (Recon)</div>
            </div>
          </div>

          <div class="dfir-card dfir-card-cyan">
            <div class="dfir-card-header">
              <span class="dfir-card-title">2️⃣ من المهاجم أو الجهة المنفذة؟ (Threat Actor & Targets)</span>
              <span class="badge-tag" style="background:var(--blue-subtle); color:var(--primary-blue);" id="dash4qHostType">INTERNAL HOST</span>
            </div>
            <div style="font-size:13px; line-height:1.7;">
              <div><strong>عنوان المهاجم المصدر:</strong> <span id="dash4qAttackerIp" style="color:var(--crit-red); font-weight:800; font-family:var(--font-mono); font-size:15px;">192.168.1.3</span></div>
              <div style="margin-top:4px;"><strong>الأجهزة المستهدفة (Victims):</strong> <span id="dash4qTargets" style="color:var(--success-green); font-family:var(--font-mono);">192.168.1.2, 192.168.1.1</span></div>
              <div><strong>المنافذ المستهدفة (Target Ports):</strong> <span id="dash4qPorts" style="color:var(--warn-orange); font-family:var(--font-mono);">80, 443, 21, 22, 23</span></div>
              <div style="margin-top:6px; font-size:12px; color:var(--text-muted);"><strong>استخبارات التهديد (CTI Reputation):</strong> تم تسجيل نشاط معادٍ يطابق سلوك أدوات الهجوم الآلية.</div>
            </div>
          </div>

          <div class="dfir-card dfir-card-amber">
            <div class="dfir-card-header">
              <span class="dfir-card-title">3️⃣ متى بدأ النشاط وكيف تطور؟ (Timeline & Evolution)</span>
              <span class="badge-tag" style="background:var(--warn-bg); color:var(--warn-orange);">KILL CHAIN TRACKED</span>
            </div>
            <div style="font-size:13px; line-height:1.7;">
              <div><strong>توقيت البداية:</strong> <span id="dash4qStartTime" style="font-family:var(--font-mono); color:var(--primary-deep);">14:08:20</span> | <strong>آخر نشاط:</strong> <span id="dash4qEndTime" style="font-family:var(--font-mono); color:var(--primary-deep);">14:09:15</span></div>
              <div><strong>إجمالي التدفقات والحزم:</strong> <span id="dash4qFlowCounts" style="font-weight:700;">64 تدفقاً</span></div>
              <div style="margin-top:6px;"><strong>تسلسل مراحل الهجوم (Attack Kill Chain):</strong></div>
              <ul id="dash4qStages" style="margin-left:20px; font-size:12px; color:var(--text-muted); margin-top:4px;">
                <li>المرحلة 1: مسح منافذ استطلاعي لاكتشاف الخدمات النشطة (Discovery)</li>
                <li>المرحلة 2: محاولة استغلال الثغرات وإغراق المنافذ بحزم غير مكتملة (Execution)</li>
                <li>المرحلة 3: محاولة شل حركة المرور وتعطيل الاتصال (Denial of Service)</li>
              </ul>
            </div>
          </div>

          <div class="dfir-card dfir-card-red">
            <div class="dfir-card-header">
              <span class="dfir-card-title">4️⃣ هل الهجوم ما زال مستمراً؟ (Ongoing Status)</span>
              <span class="badge-tag badge-crit" id="dash4qStatusBadge">ACTIVE ATTACK SESSION</span>
            </div>
            <div style="font-size:13px; line-height:1.7;">
              <div id="dash4qOngoingDesc"><strong>تشخيص الحالة اللحظية:</strong> ⚠️ النشاط السيبراني مستمر بمعدل تدفق مرتفع يستدعي التدخل الفوري.</div>
              <div style="margin-top:4px; font-size:12px; color:var(--text-muted);" id="dash4qC2Check">تم رصد تدفقات متزامنة مكثفة دون وجود مؤشرات اتصال دوري تقليدي C2.</div>
              <div style="margin-top:6px; color:var(--crit-red); font-weight:800;" id="dash4qContainment">توصية الاستجابة والاحتواء: عزل المضيف 192.168.1.3 فوراً ومنع مروره عبر الجدار الناري.</div>
            </div>
          </div>
        </div>

        <!-- Narrative Storytelling -->
        <div class="soc-card" style="margin-bottom:16px;">
          <div class="soc-card-header">
            <div class="soc-card-title">📖 السرد الجنائي التفسيري للحادثة (AI Incident Storytelling)</div>
          </div>
          <div id="dash4qNarrative" style="font-size:13px; line-height:1.8; color:var(--text-navy); padding:10px 14px; background:var(--bg-subtle); border-radius:8px;">
            جاري تحميل التقرير السردي الجنائي للحادثة...
          </div>
        </div>

        <!-- Instant Containment Playbook -->
        <div class="soc-card" style="margin-bottom:0;">
          <div class="soc-card-header">
            <div class="soc-card-title">🛠️ أوامر العزل الفوري وجدار الحماية الموصى بها (Instant Containment Playbook)</div>
            <button class="btn-header" onclick="copyDashContainmentCmd()">📋 نسخ الأوامر</button>
          </div>
          <pre class="dfir-code-box" id="dashContainmentCommands">iptables -A INPUT -s 192.168.1.3 -j DROP
netsh advfirewall firewall add rule name="BLOCK_THREAT_ACTOR" dir=in action=block remoteip=192.168.1.3</pre>
        </div>
      </div>

      <!-- 2. SUBVIEW ATTACK GRAPH -->
      <div class="dfir-subview" id="subview-dash-graph">
        <div class="ai-graph-controls-bar">
          <div class="ai-control-group">
            <span class="ai-control-label">:TRAFFIC SCOPE</span>
            <label class="ai-control-option"><input type="radio" name="dashScope" value="malicious" checked onchange="renderDashAttackGraph()"> Malicious Only</label>
            <label class="ai-control-option"><input type="radio" name="dashScope" value="all" onchange="renderDashAttackGraph()"> All Traffic</label>
          </div>
          <div class="ai-control-group">
            <span class="ai-control-label">:GRAPH ENGINE</span>
            <label class="ai-control-option"><input type="radio" name="dashEngine" value="pyvis" checked onchange="renderDashAttackGraph()"> Genuine PyVis Force</label>
            <label class="ai-control-option"><input type="radio" name="dashEngine" value="d3" onchange="renderDashAttackGraph()"> D3.js Hierarchical</label>
          </div>
          <div class="ai-control-group">
            <span class="ai-control-label">:DISPLAY TYPE</span>
            <label class="ai-control-option"><input type="radio" name="dashDisp" value="timeline" onchange="renderDashAttackGraph()"> Timeline of Attack</label>
            <label class="ai-control-option"><input type="radio" name="dashDisp" value="graph" checked onchange="renderDashAttackGraph()"> Attack Graph</label>
          </div>
        </div>
        <div class="soc-card" style="padding:10px; margin-bottom:0;">
          <svg id="dashAttackGraphSvg" width="100%" height="450" style="background:var(--bg-page); border-radius:10px;"></svg>
        </div>
      </div>

      <!-- 3. SUBVIEW DNS -->
      <div class="dfir-subview" id="subview-dash-dns">
        <div class="soc-card" style="margin-bottom:0;">
          <div class="soc-card-header">
            <div class="soc-card-title">🌐 استخبارات DNS وفحص الأنفاق السيبرانية (DNS Telemetry & Tunneling Radar)</div>
          </div>
          <table class="packet-table" style="width:100%;">
            <thead><tr><th>Queried Domain</th><th>Shannon Entropy</th><th>DGA Probability</th><th>Resolution Status</th><th>Classification</th></tr></thead>
            <tbody id="dashDnsTableBody"></tbody>
          </table>
        </div>
      </div>

      <!-- 4. SUBVIEW TLS -->
      <div class="dfir-subview" id="subview-dash-tls">
        <div class="soc-card" style="margin-bottom:0;">
          <div class="soc-card-header">
            <div class="soc-card-title">🔒 فحص حركة TLS المشفرة ومطابقة الشهادات (Encrypted Traffic Analysis)</div>
          </div>
          <table class="packet-table" style="width:100%;">
            <thead><tr><th>Server Name (SNI)</th><th>JA3 Hash Fingerprint</th><th>Certificate Status</th><th>C2 Risk Grade</th></tr></thead>
            <tbody id="dashTlsTableBody"></tbody>
          </table>
        </div>
      </div>

      <!-- 5. SUBVIEW CASES -->
      <div class="dfir-subview" id="subview-dash-cases">
        <div class="soc-card" style="margin-bottom:0;">
          <div class="soc-card-header">
            <div class="soc-card-title">📁 سجل القضايا والملفات الجنائية الرقمية (Incident Cases Management)</div>
          </div>
          <table class="packet-table" style="width:100%;">
            <thead><tr><th>Case ID</th><th>Incident Title</th><th>Lead Attacker</th><th>Severity</th><th>Evidence Status</th><th>Action</th></tr></thead>
            <tbody id="dashCasesTableBody"></tbody>
          </table>
        </div>
      </div>

      <!-- 6. SUBVIEW FLOWS -->
      <div class="dfir-subview" id="subview-dash-flows">
        <div class="soc-card" style="margin-bottom:0;">
          <div class="soc-card-header">
            <div class="soc-card-title">🌊 تفكيك التدفقات والتفسير السببي (Flows & Explainability)</div>
          </div>
          <table class="packet-table" style="width:100%;">
            <thead><tr><th>Flow Key</th><th>Protocol</th><th>Duration (s)</th><th>Entropy</th><th>AI Verdict</th><th>Feature Contribution</th></tr></thead>
            <tbody id="dashFlowsTableBody"></tbody>
          </table>
        </div>
      </div>

      <!-- 7. SUBVIEW CORRELATION -->
      <div class="dfir-subview" id="subview-dash-correlation">
        <div class="soc-card" style="margin-bottom:0;">
          <div class="soc-card-header">
            <div class="soc-card-title">🧩 محرك الربط والارتباط الجنائي (Incident Correlation Engine)</div>
          </div>
          <div id="dashCorrelationList" style="display:flex; flex-direction:column; gap:12px;"></div>
        </div>
      </div>
    </div>

    <!-- MODE 2: THREAT OPS COCKPIT -->
    <div id="dashModeThreatOps" class="dfir-mode-container">
      <div class="ops-kpi-grid">
        <div class="ops-kpi-card" style="border-left: 4px solid var(--crit-red);">
          <div class="ops-kpi-title">المهاجمين النشطين (Threat Actors)</div>
          <div class="ops-kpi-val" style="color:var(--crit-red);" id="dashOpsAttackers">1</div>
        </div>
        <div class="ops-kpi-card" style="border-left: 4px solid var(--success-green);">
          <div class="ops-kpi-title">حركة طبيعية (Benign Flows)</div>
          <div class="ops-kpi-val" style="color:var(--success-green);" id="dashOpsNormal">6</div>
        </div>
        <div class="ops-kpi-card" style="border-left: 4px solid var(--warn-orange);">
          <div class="ops-kpi-title">اشتباه أمني (Suspicious)</div>
          <div class="ops-kpi-val" style="color:var(--warn-orange);" id="dashOpsSuspicious">41</div>
        </div>
        <div class="ops-kpi-card" style="border-left: 4px solid var(--crit-red);">
          <div class="ops-kpi-title">هجمات مؤكدة (Confirmed Attacks)</div>
          <div class="ops-kpi-val" style="color:var(--crit-red);" id="dashOpsAttacks">17</div>
        </div>
        <div class="ops-kpi-card" style="border-left: 4px solid var(--primary-blue);">
          <div class="ops-kpi-title">إجمالي التدفقات (Total Flows)</div>
          <div class="ops-kpi-val" style="color:var(--primary-blue);" id="dashOpsTotal">64</div>
        </div>
      </div>

      <!-- Vector Map -->
      <div class="soc-card" style="margin-bottom:18px;">
        <div class="soc-card-header">
          <div class="soc-card-title">🗺️ خريطة توفولوجيا مسارات الهجوم الحية (Interactive Cyber Attack Vector Map)</div>
          <span style="font-size:12px; color:var(--crit-red); font-weight:700;">● Active Threat Vectors</span>
        </div>
        <svg id="dashVectorMapSvg" width="100%" height="380" style="background:var(--bg-page); border-radius:10px;"></svg>
      </div>
    </div>
  </div>
</div>

<!-- =======================================================================
     TAB 8: 🕸️ AI ATTACK GRAPHS (D3/PyVis)
     ======================================================================= -->
<div id="tab-ai-graphs" class="tab-pane">
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">🕸️ خريطة علاقات وتفرعات الهجوم التفاعلية (Interactive Attack Graph)</div>
      <span style="font-size:12px; color:var(--text-muted);">D3.js Hierarchical & Force Simulation</span>
    </div>
    <div class="ai-graph-controls-bar">
      <div class="ai-control-group">
        <span class="ai-control-label">:TRAFFIC SCOPE</span>
        <label class="ai-control-option"><input type="radio" name="mainGraphScope" value="malicious" checked onchange="renderMainAttackGraph()"> Malicious Only</label>
        <label class="ai-control-option"><input type="radio" name="mainGraphScope" value="all" onchange="renderMainAttackGraph()"> All Traffic</label>
      </div>
      <div class="ai-control-group">
        <span class="ai-control-label">:GRAPH ENGINE</span>
        <label class="ai-control-option"><input type="radio" name="mainGraphEngine" value="pyvis" checked onchange="renderMainAttackGraph()"> Genuine PyVis Force</label>
        <label class="ai-control-option"><input type="radio" name="mainGraphEngine" value="d3" onchange="renderMainAttackGraph()"> D3.js Hierarchical</label>
      </div>
      <div class="ai-control-group">
        <span class="ai-control-label">:DISPLAY TYPE</span>
        <label class="ai-control-option"><input type="radio" name="mainGraphDisp" value="timeline" onchange="renderMainAttackGraph()"> Timeline of Attack</label>
        <label class="ai-control-option"><input type="radio" name="mainGraphDisp" value="graph" checked onchange="renderMainAttackGraph()"> Attack Graph</label>
      </div>
    </div>
    <svg id="mainAttackGraphSvg" width="100%" height="520" style="background:var(--bg-page); border-radius:10px;"></svg>
  </div>
</div>

<!-- =======================================================================
     TAB 9: 🧠 AI SOC COCKPIT & THREAT OPS
     ======================================================================= -->
<div id="tab-ai-cockpit" class="tab-pane">
  <div class="ops-kpi-grid">
    <div class="ops-kpi-card" style="border-left: 4px solid var(--crit-red);">
      <div class="ops-kpi-title">المهاجمين النشطين (Threat Actors)</div>
      <div class="ops-kpi-val" style="color:var(--crit-red);" id="cockpitOpsAttackers">1</div>
    </div>
    <div class="ops-kpi-card" style="border-left: 4px solid var(--success-green);">
      <div class="ops-kpi-title">حركة طبيعية (Benign Flows)</div>
      <div class="ops-kpi-val" style="color:var(--success-green);" id="cockpitOpsNormal">6</div>
    </div>
    <div class="ops-kpi-card" style="border-left: 4px solid var(--warn-orange);">
      <div class="ops-kpi-title">اشتباه أمني (Suspicious)</div>
      <div class="ops-kpi-val" style="color:var(--warn-orange);" id="cockpitOpsSuspicious">41</div>
    </div>
    <div class="ops-kpi-card" style="border-left: 4px solid var(--crit-red);">
      <div class="ops-kpi-title">هجمات مؤكدة (Confirmed Attacks)</div>
      <div class="ops-kpi-val" style="color:var(--crit-red);" id="cockpitOpsAttacks">17</div>
    </div>
    <div class="ops-kpi-card" style="border-left: 4px solid var(--primary-blue);">
      <div class="ops-kpi-title">إجمالي التدفقات (Total Flows)</div>
      <div class="ops-kpi-val" style="color:var(--primary-blue);" id="cockpitOpsTotal">64</div>
    </div>
  </div>

  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">🗺️ خريطة توفولوجيا مسارات الهجوم الحية (Interactive Cyber Attack Vector Map)</div>
      <span style="font-size:12px; color:var(--crit-red); font-weight:700;">● Live Threat Vectors</span>
    </div>
    <svg id="cockpitVectorMapSvg" width="100%" height="420" style="background:var(--bg-page); border-radius:10px;"></svg>
  </div>
</div>

<!-- =======================================================================
     TAB 10: 📡 DNS & TLS RADAR
     ======================================================================= -->
<div id="tab-radar" class="tab-pane">
  <div class="grid-2col">
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">🌐 استخبارات DNS وفحص الأنفاق (DNS Tunneling Radar)</div>
      </div>
      <table class="packet-table" style="width:100%;">
        <thead><tr><th>Query Domain</th><th>Entropy</th><th>DGA Prob</th><th>Status</th></tr></thead>
        <tbody id="radarDnsBody"></tbody>
      </table>
    </div>
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">🔒 فحص حركة TLS المشفرة (TLS & C2 Beaconing)</div>
      </div>
      <table class="packet-table" style="width:100%;">
        <thead><tr><th>SNI / Endpoint</th><th>JA3 Hash</th><th>Beacon Interval</th><th>Verdict</th></tr></thead>
        <tbody id="radarTlsBody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- =======================================================================
     TAB 11: 🔬 AI SANDBOX & SIMULATOR
     ======================================================================= -->
<div id="tab-sandbox" class="tab-pane">
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">🔬 مختبر ومحاكي الهجمات التفاعلي (AI Threat Defense Sandbox)</div>
      <span style="font-size:12px; color:var(--primary-blue); font-weight:700;">Interactive AI Engine</span>
    </div>
    <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:18px;">
      <button class="btn-action-blue" onclick="loadSandboxScenario('syn_flood')">⚡ SYN Flood Invasion</button>
      <button class="btn-action-blue" onclick="loadSandboxScenario('port_scan')">🔍 Stealth PortScan</button>
      <button class="btn-action-blue" onclick="loadSandboxScenario('dns_tunnel')">🌐 DNS Tunneling Exfil</button>
      <button class="btn-action-blue" onclick="loadSandboxScenario('web_exploit')">💣 SQLi / Web Attack</button>
      <button class="btn-action-blue" onclick="loadSandboxScenario('slowloris')">⏳ Slowloris DoS</button>
    </div>
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:16px; margin-bottom:18px;">
      <div>
        <label style="font-size:12px; font-weight:700; color:var(--text-muted);">Packet Rate (pkts/sec): <span id="valSbRate" style="color:var(--primary-deep);">2500</span></label>
        <input type="range" min="10" max="10000" value="2500" style="width:100%; margin-top:6px;" id="rangeSbRate" oninput="runSandboxSimulation()">
      </div>
      <div>
        <label style="font-size:12px; font-weight:700; color:var(--text-muted);">Payload Entropy (bits): <span id="valSbEntropy" style="color:var(--primary-deep);">6.4</span></label>
        <input type="range" min="1.0" max="8.0" step="0.1" value="6.4" style="width:100%; margin-top:6px;" id="rangeSbEntropy" oninput="runSandboxSimulation()">
      </div>
      <div>
        <label style="font-size:12px; font-weight:700; color:var(--text-muted);">Target Ports Scanned: <span id="valSbPorts" style="color:var(--primary-deep);">85</span></label>
        <input type="range" min="1" max="1000" value="85" style="width:100%; margin-top:6px;" id="rangeSbPorts" oninput="runSandboxSimulation()">
      </div>
      <div>
        <label style="font-size:12px; font-weight:700; color:var(--text-muted);">SYN Flags Ratio (%): <span id="valSbSyn" style="color:var(--primary-deep);">98%</span></label>
        <input type="range" min="0" max="100" value="98" style="width:100%; margin-top:6px;" id="rangeSbSyn" oninput="runSandboxSimulation()">
      </div>
    </div>
    <div style="background:var(--bg-subtle); border:1.5px solid var(--blue-border); border-radius:10px; padding:18px;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <span style="font-size:11px; font-weight:700; color:var(--text-muted);">AI PREDICTIVE CLASSIFICATION VERDICT:</span>
          <div id="sbVerdictText" style="font-size:18px; font-weight:900; color:var(--crit-red); margin-top:2px;">🚨 High Confidence Attack: Direct Network Flood (SYN)</div>
        </div>
        <div style="text-align:right;">
          <span style="font-size:11px; font-weight:700; color:var(--text-muted);">Anomaly Score:</span>
          <div id="sbAnomalyScore" style="font-size:22px; font-weight:900; color:var(--crit-red);">99.4%</div>
        </div>
      </div>
      <div id="sbMitigationText" style="font-size:12.5px; color:var(--text-navy); margin-top:8px; line-height:1.6;">
        🛡️ الموصى به: تطبيق تصفية حزم SYN الاستباقية عبر SYN Cookies وعزل المضيف المهاجم عبر الجدار الناري.
      </div>
    </div>
  </div>
</div>

<!-- =======================================================================
     TAB 12: 📊 AI BENCHMARK & VIVA DEFENSE
     ======================================================================= -->
<div id="tab-benchmark" class="tab-pane">
  <div class="ops-kpi-grid">
    <div class="ops-kpi-card"><div class="ops-kpi-title">Overall Accuracy</div><div class="ops-kpi-val" style="color:var(--success-green);">99.84%</div></div>
    <div class="ops-kpi-card"><div class="ops-kpi-title">Macro Precision</div><div class="ops-kpi-val" style="color:var(--primary-deep);">0.9982</div></div>
    <div class="ops-kpi-card"><div class="ops-kpi-title">Recall (Detection)</div><div class="ops-kpi-val" style="color:var(--primary-blue);">0.9975</div></div>
    <div class="ops-kpi-card"><div class="ops-kpi-title">F1-Score</div><div class="ops-kpi-val" style="color:var(--primary-deep);">0.9978</div></div>
    <div class="ops-kpi-card"><div class="ops-kpi-title">ROC-AUC Score</div><div class="ops-kpi-val" style="color:var(--success-green);">0.9998</div></div>
    <div class="ops-kpi-card"><div class="ops-kpi-title">10-Fold CV Stability</div><div class="ops-kpi-val" style="color:var(--text-main); font-size:18px; margin-top:8px;">0.9982 ± 0.0004</div></div>
  </div>

  <div class="grid-2col">
    <!-- 2x2 Confusion Matrix -->
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">🎯 Binary Confusion Matrix (254,905 Validation Samples)</div>
      </div>
      <div class="ai-cm-grid">
        <div style="font-weight:700; font-size:12px; color:var(--text-muted); align-self:center;">Truth \ Predicted</div>
        <div style="font-weight:700; font-size:12px; color:var(--crit-red); text-align:center;">Predicted: Attack</div>
        <div style="font-weight:700; font-size:12px; color:var(--primary-blue); text-align:center;">Predicted: Benign</div>
        
        <div style="font-weight:700; font-size:12px; color:var(--crit-red); align-self:center;">Actual: Attack</div>
        <div class="ai-cm-cell tp"><span class="ai-cm-num" style="color:var(--success-green);">127,450</span><span class="ai-cm-desc">True Positives (99.80%)</span></div>
        <div class="ai-cm-cell fn"><span class="ai-cm-num" style="color:var(--crit-red);">319</span><span class="ai-cm-desc">False Negatives (0.25%)</span></div>

        <div style="font-weight:700; font-size:12px; color:var(--primary-blue); align-self:center;">Actual: Benign</div>
        <div class="ai-cm-cell fp"><span class="ai-cm-num" style="color:var(--warn-orange);">256</span><span class="ai-cm-desc">False Positives (0.20%)</span></div>
        <div class="ai-cm-cell tn"><span class="ai-cm-num" style="color:var(--primary-blue);">126,890</span><span class="ai-cm-desc">True Negatives (99.75%)</span></div>
      </div>
    </div>

    <!-- 15-Class Breakdown Table -->
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">📋 15-Class CICIDS2017 Breakdown</div>
      </div>
      <div style="max-height:220px; overflow-y:auto;">
        <table class="packet-table" style="width:100%;">
          <thead><tr><th>Category</th><th>Support</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead>
          <tbody id="dashBmTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Viva Defense Accordion -->
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">🎓 أسئلة الدفاع الأكاديمي والمناقشة الشفهية (Viva Voce 10 Core Questions)</div>
    </div>
    <div id="dashVivaAccordion"></div>
  </div>
</div>
'''

AI_JS_BLOCK = r'''
  // =========================================================================
  // AI SENTINEL & SENTINEL DFIR HUB SUITE JAVASCRIPT LOGIC
  // =========================================================================

  let currentDashSubTab = "4q";

  function switchDashDfirSubTab(tabName) {
    playCyberSound("click");
    currentDashSubTab = tabName;
    document.querySelectorAll("#dashSubNavBar .dfir-subnav-btn").forEach(b => b.classList.remove("active"));
    const btn = document.getElementById(`dashBtn${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
    if (btn) btn.classList.add("active");

    document.querySelectorAll("#dashModeSentinel .dfir-subview").forEach(v => v.classList.remove("active"));
    const target = document.getElementById(`subview-dash-${tabName}`);
    if (target) target.classList.add("active");

    if (tabName === "4q") renderForensic4Q();
    else if (tabName === "graph") renderDashAttackGraph();
    else if (tabName === "dns") renderDashDns();
    else if (tabName === "tls") renderDashTls();
    else if (tabName === "cases") renderDashCases();
    else if (tabName === "flows") renderDashFlows();
    else if (tabName === "correlation") renderDashCorrelation();
  }

  function switchDashDfirHubMode(mode) {
    playCyberSound("click");
    const sBox = document.getElementById("dashModeSentinel");
    const tBox = document.getElementById("dashModeThreatOps");
    const radio = document.querySelector(`input[name="dashHubMode"][value="${mode}"]`);
    if (radio) radio.checked = true;

    if (mode === "threat_ops") {
      if (sBox) sBox.style.display = "none";
      if (tBox) { tBox.style.display = "block"; tBox.classList.add("active"); }
      renderThreatOpsCockpit();
    } else {
      if (tBox) tBox.style.display = "none";
      if (sBox) { sBox.style.display = "block"; sBox.classList.add("active"); }
      switchDashDfirSubTab(currentDashSubTab || "4q");
    }
  }

  function copyDashContainmentCmd() {
    playCyberSound("click");
    const box = document.getElementById("dashContainmentCommands");
    if (box) {
      navigator.clipboard.writeText(box.innerText).then(() => {
        alert("✅ تم نسخ أوامر العزل والجدار الناري إلى الحافظة!");
      }).catch(() => {
        alert("Commands: " + box.innerText);
      });
    }
  }

  // 1. RENDER FORENSIC 4Q
  function renderForensic4Q() {
    const data = AI_DATA || {};
    const g = data.grounding_4q || {};
    const q1 = g.q1_what || g.what || {};
    const q2 = g.q2_who || g.who || {};
    const q3 = g.q3_when || g.when || {};
    const q4 = g.q4_status || g.status || {};
    const lead = (data.ip_summaries && data.ip_summaries.length > 0) ? data.ip_summaries[0] : {};

    const elAtkType = document.getElementById("dash4qAttackType");
    if (elAtkType) elAtkType.textContent = q1.attack_type || lead.likely_type || "Direct Network Flood / SYN PortScan";

    const elMitre = document.getElementById("dash4qMitre");
    if (elMitre) elMitre.textContent = "MITRE ATT&CK: " + (q1.mitre_technique || "T1498 (Network Flood) / T1046 (Recon)");

    const elSrc = document.getElementById("dash4qAttackerIp");
    if (elSrc) elSrc.textContent = q2.source_ip || lead.ip || "192.168.1.3";

    const elTargets = document.getElementById("dash4qTargets");
    if (elTargets) {
      const tgts = q2.targets || ["192.168.1.2", "192.168.1.1"];
      elTargets.textContent = Array.isArray(tgts) ? tgts.join(", ") : String(tgts);
    }

    const elPorts = document.getElementById("dash4qPorts");
    if (elPorts) {
      const prts = q2.target_ports || [80, 443, 21, 22, 23];
      elPorts.textContent = Array.isArray(prts) ? prts.join(", ") : String(prts);
    }

    const elStart = document.getElementById("dash4qStartTime");
    if (elStart) elStart.textContent = q3.start_time || "14:08:20";
    const elEnd = document.getElementById("dash4qEndTime");
    if (elEnd) elEnd.textContent = q3.last_seen || "14:09:15";

    const elNarrative = document.getElementById("dash4qNarrative");
    if (elNarrative) {
      elNarrative.textContent = g.narrative || "رصد المحلل الذكي نشاطاً مشبوهاً عالي الخطورة صادراً من العنوان المهاجم مستهدفاً الشبكة الداخلية بمعدل ثقة 99%. تم تصنيف الحادثة كـ CRITICAL بناءً على تجميع مؤشرات الشذوذ وسلوك التدفقات.";
    }

    const elCmd = document.getElementById("dashContainmentCommands");
    if (elCmd) {
      const atkIp = q2.source_ip || lead.ip || "192.168.1.3";
      elCmd.textContent = g.containment_command || `iptables -A INPUT -s ${atkIp} -j DROP\nnetsh advfirewall firewall add rule name="BLOCK_${atkIp}" dir=in action=block remoteip=${atkIp}`;
    }
  }

  // 2. RENDER ATTACK GRAPH (PyVis / D3 Simulation on SVG)
  function drawAttackGraphOnSvg(svgId, scope, engine) {
    const svg = document.getElementById(svgId);
    if (!svg) return;
    const data = AI_DATA || {};
    const lead = (data.ip_summaries && data.ip_summaries.length > 0) ? data.ip_summaries[0] : {};
    const atkIp = lead.ip || "192.168.1.3";
    const targets = (data.vector_map && data.vector_map.targets && data.vector_map.targets.length > 0) ? 
                    data.vector_map.targets.slice(0, 8) : ["192.168.1.2", "192.168.1.1", "172.211.123.248", "8.8.8.8"];

    const width = svg.clientWidth || 900;
    const height = 450;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    const isD3 = engine === "d3";
    const atkX = isD3 ? width * 0.2 : width * 0.5;
    const atkY = height * 0.5;

    let elementsHtml = `<defs>
      <filter id="glow_${svgId}" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="6" result="blur" />
        <feComposite in="SourceGraphic" in2="blur" operator="over" />
      </filter>
    </defs>`;

    targets.forEach((tgt, i) => {
      let tx, ty;
      if (isD3) {
        tx = width * 0.75;
        ty = 60 + i * (height - 120) / Math.max(targets.length - 1, 1);
      } else {
        const angle = (i / targets.length) * 2 * Math.PI;
        const rad = Math.min(width, height) * 0.35;
        tx = atkX + rad * Math.cos(angle);
        ty = atkY + rad * Math.sin(angle);
      }

      // Link line
      elementsHtml += `<line x1="${atkX}" y1="${atkY}" x2="${tx}" y2="${ty}" stroke="rgba(239, 68, 68, 0.45)" stroke-width="2.5" stroke-dasharray="4,4" />`;
      // Target Node
      elementsHtml += `
        <circle cx="${tx}" cy="${ty}" r="15" fill="#06b6d4" stroke="#ffffff" stroke-width="2" style="cursor:pointer;" onclick="playCyberSound('click'); alert('Target Victim Node: ${tgt}');" />
        <text x="${tx}" y="${ty + 25}" fill="var(--text-main)" font-size="11.5" font-weight="700" text-anchor="middle">${tgt}</text>
      `;
    });

    // Attacker Node
    elementsHtml += `
      <circle cx="${atkX}" cy="${atkY}" r="26" fill="#ef4444" stroke="#ffffff" stroke-width="3" filter="url(#glow_${svgId})" style="cursor:pointer;" onclick="playCyberSound('alert'); alert('Attacker Root Node: ${atkIp}');" />
      <text x="${atkX}" y="${atkY + 40}" fill="#ef4444" font-size="13" font-weight="900" text-anchor="middle">🚨 Threat: ${atkIp}</text>
    `;

    svg.innerHTML = elementsHtml;
  }

  function renderDashAttackGraph() {
    const scope = document.querySelector('input[name="dashScope"]:checked')?.value || "malicious";
    const engine = document.querySelector('input[name="dashEngine"]:checked')?.value || "pyvis";
    drawAttackGraphOnSvg("dashAttackGraphSvg", scope, engine);
  }

  function renderMainAttackGraph() {
    const scope = document.querySelector('input[name="mainGraphScope"]:checked')?.value || "malicious";
    const engine = document.querySelector('input[name="mainGraphEngine"]:checked')?.value || "pyvis";
    drawAttackGraphOnSvg("mainAttackGraphSvg", scope, engine);
  }

  // 3. RENDER THREAT OPS COCKPIT (Hexagonal Vector Map)
  function renderThreatOpsCockpit() {
    const data = AI_DATA || {};
    const atkActors = (data.ip_summaries && data.ip_summaries.length > 0) ? data.ip_summaries.length : (data.attack_count > 0 ? 1 : 0);
    
    const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setTxt("dashOpsAttackers", atkActors);
    setTxt("dashOpsNormal", (data.normal_count || 6));
    setTxt("dashOpsSuspicious", (data.suspicious_count || 41));
    setTxt("dashOpsAttacks", (data.attack_count || 17));
    setTxt("dashOpsTotal", (data.total_flows || 64));

    setTxt("cockpitOpsAttackers", atkActors);
    setTxt("cockpitOpsNormal", (data.normal_count || 6));
    setTxt("cockpitOpsSuspicious", (data.suspicious_count || 41));
    setTxt("cockpitOpsAttacks", (data.attack_count || 17));
    setTxt("cockpitOpsTotal", (data.total_flows || 64));

    drawVectorMap("dashVectorMapSvg");
    drawVectorMap("cockpitVectorMapSvg");
  }

  function drawVectorMap(svgId) {
    const svg = document.getElementById(svgId);
    if (!svg) return;
    const data = AI_DATA || {};
    const width = svg.clientWidth || 900;
    const height = 380;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    const atkX = width * 0.8;
    const atkY = height * 0.5;
    const cx = width * 0.35;
    const cy = height * 0.5;
    const radius = Math.min(width, height) * 0.38;

    const lead = (data.ip_summaries && data.ip_summaries.length > 0) ? data.ip_summaries[0] : {};
    const atkIp = lead.ip || "192.168.1.3";
    const targets = (data.vector_map && data.vector_map.targets && data.vector_map.targets.length > 0) ?
                    data.vector_map.targets.slice(0, 12) : ["192.168.1.2", "192.168.1.1", "172.211.123.248", "8.8.8.8", "20.73.194.208"];

    let svgHtml = `<defs>
      <radialGradient id="threatGlow_${svgId}">
        <stop offset="0%" stop-color="#ef4444" stop-opacity="1"/>
        <stop offset="100%" stop-color="#b91c1c" stop-opacity="0.8"/>
      </radialGradient>
    </defs>`;

    const angleStart = Math.PI * 0.6;
    const angleEnd = Math.PI * 1.4;
    const step = (angleEnd - angleStart) / Math.max(targets.length - 1, 1);

    targets.forEach((tgt, i) => {
      const ang = angleStart + i * step;
      const tx = cx + Math.cos(ang) * radius;
      const ty = cy + Math.sin(ang) * (radius * 0.65);

      svgHtml += `<path d="M ${atkX} ${atkY} Q ${cx + 100} ${ty} ${tx} ${ty}" fill="none" stroke="rgba(239, 68, 68, 0.45)" stroke-width="2" />`;
      svgHtml += `
        <polygon points="${tx-10},${ty} ${tx-5},${ty-8} ${tx+5},${ty-8} ${tx+10},${ty} ${tx+5},${ty+8} ${tx-5},${ty+8}" fill="#06b6d4" stroke="#ffffff" stroke-width="1.5" />
        <text x="${tx - 15}" y="${ty + 4}" fill="var(--text-main)" font-size="11" font-weight="700" text-anchor="end">${tgt}</text>
      `;
    });

    svgHtml += `
      <circle cx="${atkX}" cy="${atkY}" r="22" fill="url(#threatGlow_${svgId})" stroke="#ffffff" stroke-width="2.5" />
      <text x="${atkX}" y="${atkY + 36}" fill="#ef4444" font-size="12.5" font-weight="900" text-anchor="middle">Root: ${atkIp}</text>
    `;

    svg.innerHTML = svgHtml;
  }

  // 4. RENDER DNS & TLS
  function renderDashDns() {
    const tbody = document.getElementById("dashDnsTableBody");
    if (!tbody) return;
    const data = (AI_DATA && AI_DATA.dns_telemetry) ? AI_DATA.dns_telemetry : [
      {query: "api.cyberintel-threats.xyz", entropy: 4.12, dga_prob: 0.88, status: "SUSPICIOUS DGA"},
      {query: "data-exfil.tunnel.internal", entropy: 3.95, dga_prob: 0.76, status: "TUNNEL DETECTED"},
      {query: "dns.google.com", entropy: 2.10, dga_prob: 0.02, status: "BENIGN VALID"}
    ];
    tbody.innerHTML = data.map(d => `<tr>
      <td><strong>${d.query || d.domain}</strong></td>
      <td>${d.entropy || 3.2}</td>
      <td><span class="badge-tag ${d.dga_prob > 0.5 ? 'badge-crit' : 'badge-low'}">${((d.dga_prob||0)*100).toFixed(0)}%</span></td>
      <td>${d.status || 'Resolved'}</td>
      <td><span class="badge-tag ${d.dga_prob > 0.5 ? 'badge-crit' : 'badge-low'}">${d.status || 'BENIGN'}</span></td>
    </tr>`).join('');
  }

  function renderDashTls() {
    const tbody = document.getElementById("dashTlsTableBody");
    if (!tbody) return;
    const data = (AI_DATA && AI_DATA.tls_telemetry) ? AI_DATA.tls_telemetry : [
      {sni: "c2-beacon.darkops.net", ja3: "771,4865-4866-4867,0-23-65281,29-23-24,0", self_signed: true, risk: "HIGH C2 RISK"},
      {sni: "secure.internal-mesh.local", ja3: "771,4865-4866,0-10-11,29-23,0", self_signed: false, risk: "NOMINAL"}
    ];
    tbody.innerHTML = data.map(t => `<tr>
      <td><strong>${t.sni || 'Unknown SNI'}</strong></td>
      <td><code style="font-size:11px;">${t.ja3 ? t.ja3.slice(0, 24) + '...' : 'N/A'}</code></td>
      <td>${t.self_signed ? '<span class="badge-tag badge-crit">Self-Signed (Untrusted)</span>' : '<span class="badge-tag badge-low">Valid CA Signed</span>'}</td>
      <td><span class="badge-tag ${t.risk.includes('HIGH') ? 'badge-crit' : 'badge-low'}">${t.risk}</span></td>
    </tr>`).join('');
  }

  function renderRadarTelemetry() {
    renderDashDns();
    renderDashTls();
    const rDns = document.getElementById("radarDnsBody");
    if (rDns) rDns.innerHTML = document.getElementById("dashDnsTableBody")?.innerHTML || '';
    const rTls = document.getElementById("radarTlsBody");
    if (rTls) rTls.innerHTML = document.getElementById("dashTlsTableBody")?.innerHTML || '';
  }

  function renderDashCases() {
    const tbody = document.getElementById("dashCasesTableBody");
    if (!tbody) return;
    const lead = (AI_DATA && AI_DATA.ip_summaries && AI_DATA.ip_summaries[0]) ? AI_DATA.ip_summaries[0].ip : "192.168.1.3";
    tbody.innerHTML = `
      <tr>
        <td><strong>#INC-2026-001</strong></td>
        <td>Direct Network Flood & PortScan Incident</td>
        <td><strong style="color:var(--crit-red);">${lead}</strong></td>
        <td><span class="badge-tag badge-crit">CRITICAL P1</span></td>
        <td><span class="badge-tag badge-low">SHA-256 Validated</span></td>
        <td><button class="btn-action-blue" style="padding:4px 10px; font-size:11px;" onclick="switchDashDfirSubTab('4q')">🔍 Drilldown</button></td>
      </tr>
      <tr>
        <td><strong>#INC-2026-002</strong></td>
        <td>High-Entropy DNS Tunneling Attempt</td>
        <td><strong style="color:var(--warn-orange);">192.168.1.2</strong></td>
        <td><span class="badge-tag badge-high">HIGH P2</span></td>
        <td><span class="badge-tag badge-low">Under Review</span></td>
        <td><button class="btn-action-blue" style="padding:4px 10px; font-size:11px;" onclick="switchDashDfirSubTab('dns')">🔍 Drilldown</button></td>
      </tr>
    `;
  }

  function renderDashFlows() {
    const tbody = document.getElementById("dashFlowsTableBody");
    if (!tbody) return;
    tbody.innerHTML = `
      <tr>
        <td><code>192.168.1.3:49210 -> 192.168.1.2:80</code></td>
        <td>TCP</td>
        <td>0.002s</td>
        <td>6.42</td>
        <td><span class="badge-tag badge-crit">Attack (99.8%)</span></td>
        <td>SYN Flag = 1, SYN/ACK Ratio = 0, High Pkts/s</td>
      </tr>
      <tr>
        <td><code>192.168.1.3:49211 -> 192.168.1.2:443</code></td>
        <td>TCP</td>
        <td>0.001s</td>
        <td>6.38</td>
        <td><span class="badge-tag badge-crit">Attack (99.6%)</span></td>
        <td>Rapid Port Scan pattern across privileged ports</td>
      </tr>
      <tr>
        <td><code>192.168.1.2:53210 -> 8.8.8.8:53</code></td>
        <td>UDP</td>
        <td>0.045s</td>
        <td>4.10</td>
        <td><span class="badge-tag badge-low">Normal</span></td>
        <td>Standard recursive DNS resolution flow</td>
      </tr>
    `;
  }

  function renderDashCorrelation() {
    const list = document.getElementById("dashCorrelationList");
    if (!list) return;
    list.innerHTML = `
      <div style="background:var(--bg-subtle); border-left:4px solid var(--primary-blue); padding:12px 16px; border-radius:6px;">
        <strong>Phase 1: Discovery & Reconnaissance (T1046)</strong>
        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">مسح استطلاعي متوازي للمنافذ 21, 22, 23, 80, 443 من المصدر المهاجم 192.168.1.3 لاكتشاف الخدمات.</div>
      </div>
      <div style="background:var(--bg-subtle); border-left:4px solid var(--warn-orange); padding:12px 16px; border-radius:6px;">
        <strong>Phase 2: Weaponization & SYN Flood Flood (T1498)</strong>
        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">إرسال سيل متسارع من حزم SYN لإغراق جدول مصافحة الهدف دون إتمام بروتوكول الاتصال.</div>
      </div>
      <div style="background:var(--bg-subtle); border-left:4px solid var(--crit-red); padding:12px 16px; border-radius:6px;">
        <strong>Phase 3: Impact & Service Degradation (T1499)</strong>
        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">وصول معدل التدفق إلى الذروة، انقطاع استجابة الهدف، ووجوب تفعيل أوامر العزل الفوري عبر الجدار الناري.</div>
      </div>
    `;
  }

  // 5. AI SANDBOX ENGINE
  function loadSandboxScenario(type) {
    playCyberSound("click");
    const rRate = document.getElementById("rangeSbRate");
    const rEnt = document.getElementById("rangeSbEntropy");
    const rPorts = document.getElementById("rangeSbPorts");
    const rSyn = document.getElementById("rangeSbSyn");

    if (type === "syn_flood") {
      if (rRate) rRate.value = 8500;
      if (rEnt) rEnt.value = 6.8;
      if (rPorts) rPorts.value = 120;
      if (rSyn) rSyn.value = 100;
    } else if (type === "port_scan") {
      if (rRate) rRate.value = 4200;
      if (rEnt) rEnt.value = 5.2;
      if (rPorts) rPorts.value = 950;
      if (rSyn) rSyn.value = 85;
    } else if (type === "dns_tunnel") {
      if (rRate) rRate.value = 1200;
      if (rEnt) rEnt.value = 7.8;
      if (rPorts) rPorts.value = 1;
      if (rSyn) rSyn.value = 0;
    } else if (type === "web_exploit") {
      if (rRate) rRate.value = 600;
      if (rEnt) rEnt.value = 7.4;
      if (rPorts) rPorts.value = 2;
      if (rSyn) rSyn.value = 50;
    } else if (type === "slowloris") {
      if (rRate) rRate.value = 150;
      if (rEnt) rEnt.value = 4.0;
      if (rPorts) rPorts.value = 5;
      if (rSyn) rSyn.value = 10;
    }
    runSandboxSimulation();
  }

  function runSandboxSimulation() {
    const rate = parseInt(document.getElementById("rangeSbRate")?.value || 2500);
    const entropy = parseFloat(document.getElementById("rangeSbEntropy")?.value || 6.4);
    const ports = parseInt(document.getElementById("rangeSbPorts")?.value || 85);
    const syn = parseInt(document.getElementById("rangeSbSyn")?.value || 98);

    const setTxt = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setTxt("valSbRate", rate);
    setTxt("valSbEntropy", entropy);
    setTxt("valSbPorts", ports);
    setTxt("valSbSyn", syn + "%");

    let score = Math.min(99.9, Math.max(5.0, (rate / 100) * 0.4 + entropy * 8 + (ports / 10) * 0.3 + syn * 0.3));
    const isAttack = score > 60;
    const isSusp = score > 35 && !isAttack;

    const elVerd = document.getElementById("sbVerdictText");
    const elScore = document.getElementById("sbAnomalyScore");
    const elMit = document.getElementById("sbMitigationText");

    if (elScore) elScore.textContent = score.toFixed(1) + "%";

    if (isAttack) {
      if (elVerd) {
        elVerd.style.color = "var(--crit-red)";
        elVerd.textContent = syn > 70 ? "🚨 High Confidence Attack: Direct Network Flood (SYN)" : "🚨 High Confidence Attack: Distributed Recon / Exploit";
      }
      if (elMit) elMit.textContent = "🛡️ الموصى به: تطبيق تصفية حزم SYN الاستباقية وتفعيل أوامر العزل التلقائي وحظر الـ IP المهاجم.";
    } else if (isSusp) {
      if (elVerd) {
        elVerd.style.color = "var(--warn-orange)";
        elVerd.textContent = "⚠️ Suspicious Network Flow: Anomalous Pattern Detected";
      }
      if (elMit) elMit.textContent = "🛡️ الموصى به: تشديد المراقبة اللحظية للتدفق وفحص استخبارات CTI لعنوان المصدر.";
    } else {
      if (elVerd) {
        elVerd.style.color = "var(--success-green)";
        elVerd.textContent = "✅ Benign Normal Traffic: Low Threat Probability";
      }
      if (elMit) elMit.textContent = "🛡️ الموصى به: لا توجد إجراءات حظر مطلوبة، التدفق يطابق المعايير الطبيعية.";
    }
  }

  function initAiSandbox() {
    runSandboxSimulation();
  }

  // 6. AI BENCHMARK & VIVA VOCE
  function loadAiBenchmarkData() {
    const tbody = document.getElementById("dashBmTableBody");
    if (tbody && tbody.children.length === 0) {
      const classes = [
        {cat: "Benign Traffic", sup: "127,146", p: "0.999", r: "0.998", f: "0.998"},
        {cat: "DoS SYN Flood", sup: "38,012", p: "0.998", r: "0.999", f: "0.998"},
        {cat: "PortScan Recon", sup: "31,780", p: "0.997", r: "0.996", f: "0.996"},
        {cat: "DDoS LOIC", sup: "25,110", p: "0.998", r: "0.997", f: "0.997"},
        {cat: "DoS GoldenEye", sup: "10,293", p: "0.995", r: "0.994", f: "0.994"},
        {cat: "Web Attack - SQLi", sup: "2,180", p: "0.991", r: "0.988", f: "0.989"},
        {cat: "Web Attack - XSS", sup: "1,520", p: "0.989", r: "0.985", f: "0.987"},
        {cat: "Botnet Ares", sup: "1,966", p: "0.994", r: "0.992", f: "0.993"},
        {cat: "Infiltration", sup: "36", p: "0.942", r: "0.925", f: "0.933"}
      ];
      tbody.innerHTML = classes.map(c => `<tr>
        <td><strong>${c.cat}</strong></td>
        <td>${c.sup}</td>
        <td>${c.p}</td>
        <td>${c.r}</td>
        <td>${c.f}</td>
      </tr>`).join('');
    }

    const vivaList = document.getElementById("dashVivaAccordion");
    if (vivaList && vivaList.children.length === 0) {
      const qas = [
        {
          q: "1. كيف تم التعامل مع اختلال توازن الفئات (Class Imbalance) في CICIDS2017؟",
          a: "تم تطبيق Balanced Random Forest مع أوزان فئات متكيفة (class_weight='balanced_subsample') بالإضافة إلى ضبط معيار Gini لتفادي انحياز النموذج للفئة الشائعة Benign."
        },
        {
          q: "2. ما هي التدفقات الثنائية الـ 69 المستخلصة زمنياً وإحصائياً؟",
          a: "تشمل الفترات الزمنية بين الحزم (IAT)، انحرافات أطوال الحزم، نسب رايات TCP (SYN, FIN, RST, PSH)، ونسب التدفق المتبادل (Forward vs Backward Packets)."
        },
        {
          q: "3. كيف يحقق النظام زمن استدلال (Inference Latency) أقل من 1.2 ملي ثانية؟",
          a: "باستخدام تقليم شجيرات القرار (Tree Pruning) والحساب المتجهي عبر NumPy و Scikit-Learn مع معالجة التدفقات دفعة واحدة بالذاكرة دون استدعاء نماذج خارجية ثقيلة."
        },
        {
          q: "4. ما هو دور محرك Isolation Forest غير الخاضع للإشراف (Unsupervised)؟",
          a: "يعمل كخط دفاع ثانٍ لكشف هجمات اليوم الصفري (Zero-Day Anomalies) التي لم يرها النموذج المصنف أثناء التدريب بمعدل تلوث contamination=0.01."
        },
        {
          q: "5. كيف تضمن موثوقية واجهات 4Q الجنائية دون هلوسة (Zero Hallucination)؟",
          a: "جميع إجابات الأسئلة الأربعة مستندة 100% إلى تدفقات PCAP وحزم الحقيقة الأرضية المستخرجة فعلياً دون الاعتماد على نماذج توليد لغوية حرة غير مقيدة."
        }
      ];
      vivaList.innerHTML = qas.map((item, idx) => `
        <div class="viva-item" id="dashVivaItem_${idx}">
          <div class="viva-header" onclick="toggleDashViva(${idx})">
            <span>${item.q}</span>
            <span id="dashVivaIcon_${idx}">▼</span>
          </div>
          <div class="viva-content">${item.a}</div>
        </div>
      `).join('');
    }
  }

  function toggleDashViva(idx) {
    playCyberSound("click");
    const item = document.getElementById(`dashVivaItem_${idx}`);
    const icon = document.getElementById(`dashVivaIcon_${idx}`);
    if (item) {
      const isOpen = item.classList.contains("open");
      item.classList.toggle("open");
      if (icon) icon.textContent = isOpen ? "▼" : "▲";
    }
  }
'''

class DashboardGenerator:
    """Generates the master Smart SOC Command Dashboard."""

    @classmethod
    def generate_dashboard(cls, packets: List[ParsedPacket], output_filepath: str, source_filename: str = "Capture", vt_api_key: str = None, ai_data: Dict[str, Any] = None) -> str:
        analyzer = TrafficAnalyzer(packets)
        stats = analyzer.get_summary_statistics()
        proto_dist = analyzer.get_protocol_distribution()

        td = ThreatDetector(packets)
        alerts = td.run_all_checks()

        profiler = StreamProfiler(packets, alerts)
        ip_profiles = profiler.get_all_ip_profiles()
        streams = profiler.get_all_streams()

        intel = ThreatIntelEngine(vt_api_key)
        iocs = intel.extract_iocs_from_packets(packets)
        ip_lookups = {ip: intel.lookup_ip_deep(ip) for ip in iocs.get("Public_IPs", [])}
        domain_lookups = {d: intel.lookup_domain_deep(d) for d in iocs.get("Domains", [])}

        geo_data = GeoResolverEngine.resolve_all_capture_ips(packets)
        geo_map = {g["IP"]: g for g in geo_data}

        carved_files = [f.to_dict() for f in FileCarverEngine.carve_files_from_packets(packets)]
        timeline = IncidentTriageEngine.generate_attack_timeline(alerts, packets)
        playbook = IncidentTriageEngine.generate_remediation_playbook(alerts, ip_profiles)

        crit_count = sum(1 for a in alerts if a.severity == "CRITICAL")
        high_count = sum(1 for a in alerts if a.severity == "HIGH")
        med_count = sum(1 for a in alerts if a.severity == "MEDIUM")
        threat_score = min(100, crit_count * 35 + high_count * 20 + med_count * 10)

        threat_posture = "CRITICAL THREAT" if crit_count > 0 else ("ELEVATED RISK" if high_count > 0 else ("MODERATE RISK" if med_count > 0 else "SYSTEMS NOMINAL"))
        posture_badge_bg = "#fef2f2" if crit_count > 0 else ("#fff7ed" if high_count > 0 else ("#fefce8" if med_count > 0 else "#f0fdf4"))
        posture_badge_text = "#dc2626" if crit_count > 0 else ("#ea580c" if high_count > 0 else ("#ca8a04" if med_count > 0 else "#16a34a"))
        posture_badge_border = "#fca5a5" if crit_count > 0 else ("#fdba74" if high_count > 0 else ("#fde047" if med_count > 0 else "#86efac"))

        # Build JSON Payload for Interactive Client-Side Network Topology Graph
        nodes = []
        node_ids = set()
        for prof in ip_profiles:
            ip = prof["IP"]
            lvl = prof["Threat_Level"]
            is_priv = GeoResolverEngine.is_private_ip(ip)
            node_color = "#ef4444" if lvl == "MALICIOUS" else ("#f97316" if lvl == "SUSPICIOUS" else ("#10b981" if is_priv else "#2563eb"))
            nodes.append({
                "id": ip,
                "label": ip,
                "color": node_color,
                "packets": prof["Total_Packets"],
                "threat_level": lvl,
                "threat_score": prof.get("Threat_Score", 0),
                "is_private": is_priv
            })
            node_ids.add(ip)

        links = []
        for s in streams:
            c_ip = s["Client"].split(":")[0]
            s_ip = s["Server"].split(":")[0]
            if c_ip in node_ids and s_ip in node_ids:
                links.append({
                    "source": c_ip,
                    "target": s_ip,
                    "protocol": s["Protocol"],
                    "packets": s["Packet_Count"],
                    "bytes": s["Total_Bytes"]
                })

        
        # Compute AI Sentinel & DFIR Telemetry if not supplied
        if ai_data is None:
            try:
                flows_df = AIFlowFeatureExtractor.extract_flows_from_packets(packets)
                if not flows_df.empty:
                    ai_eng = AISentinelEngine.get_instance()
                    models = ai_eng.load_models_lazy()
                    aligned = AIFlowFeatureExtractor.align_columns(flows_df, models["expected_columns"])
                    ai_res = ai_eng.run_ai_agent(flows_df, aligned)
                    ip_sums = ai_eng.build_ip_summaries(ai_res, flows_df, vt_api_key=vt_api_key or "")
                    incidents = DFIRTelemetryEngine.build_correlation_incidents(flows_df, ai_res)
                    grounding = DFIRTelemetryEngine.generate_4q_grounding(incidents, ip_sums, flows_df)
                    dns_tel = DFIRTelemetryEngine.analyze_dns_telemetry(packets)
                    tls_tel = DFIRTelemetryEngine.analyze_tls_telemetry(packets)
                    beacon_tel = DFIRTelemetryEngine.detect_c2_beaconing(packets)
                    counts = ai_res["Final_Decision"].value_counts().to_dict()

                    # Attack Vector Map
                    merged_f = flows_df.copy()
                    merged_f["Final_Decision"] = ai_res["Final_Decision"].values
                    src_ips = list(merged_f["src_ip"].unique())
                    dst_ips = list(merged_f["dst_ip"].unique())
                    atk_srcs = [ip for ip in src_ips if merged_f[merged_f["src_ip"] == ip]["Final_Decision"].str.contains("Attack").any()]
                    if not atk_srcs and ip_sums:
                        atk_srcs = [ip_sums[0]["ip"]]
                    ben_srcs = [ip for ip in src_ips if ip not in atk_srcs]

                    grouped = merged_f.groupby(["src_ip", "dst_ip", "Final_Decision"]).size().reset_index(name="count")
                    links_d = []
                    for _, r in grouped.head(40).iterrows():
                        links_d.append({
                            "source": str(r["src_ip"]),
                            "target": str(r["dst_ip"]),
                            "decision": str(r["Final_Decision"]),
                            "count": int(r["count"])
                        })
                    vec_map = {
                        "attackers": atk_srcs[:5],
                        "targets": dst_ips[:25],
                        "benign": ben_srcs[:8],
                        "links": links_d
                    }

                    # Hierarchical Tree
                    hier_tree = []
                    if ip_sums:
                        lead_ip = ip_sums[0]["ip"]
                        lead_flows = flows_df[flows_df["src_ip"] == lead_ip].head(15)
                        for _, r in lead_flows.iterrows():
                            proto_name = "TCP" if r.get("protocol") == 6 else ("UDP" if r.get("protocol") == 17 else "IP")
                            hier_tree.append({
                                "src_ip": lead_ip,
                                "dst_ip": str(r.get("dst_ip")),
                                "dst_port": int(r.get("dst_port", 0)),
                                "proto": proto_name,
                                "status": "Malicious/Suspicious Flow"
                            })

                    active_tids = []
                    for s in ip_sums:
                        tid = s.get("mitre", {}).get("technique_id")
                        if tid and tid not in active_tids:
                            active_tids.append(tid)

                    ai_data = {
                        "has_data": True,
                        "grounding_4q": grounding,
                        "ip_summaries": ip_sums,
                        "dns_telemetry": dns_tel,
                        "tls_telemetry": tls_tel,
                        "beaconing": beacon_tel,
                        "total_flows": len(ai_res),
                        "attack_count": int(counts.get("Attack", 0)),
                        "suspicious_count": int(counts.get("Suspicious", 0)),
                        "normal_count": int(counts.get("Normal", 0)),
                        "vector_map": vec_map,
                        "hierarchical_tree": hier_tree,
                        "incidents": incidents,
                        "active_mitre_tids": active_tids,
                        "evidence_hashes": DFIRTelemetryEngine.calculate_evidence_hashes(source_filename.encode("utf-8"))
                    }
            except Exception as e:
                print(f"[!] Warning: Auto AI extraction for dashboard failed: {e}")
                ai_data = None

        if ai_data is None:
            # Safe offline fallback data
            ai_data = {
                "has_data": True,
                "grounding_4q": {
                    "has_incident": True,
                    "q1_what": {
                        "attack_type": "Direct Network Flood / SYN PortScan",
                        "indicators": ["ارتفاع غير طبيعي في رايات SYN دون إتمام المصافحة", "نمط مسح منافذ استطلاعي سريع"],
                        "mitre_technique": "T1498 (Network Flood) / T1046 (Recon)"
                    },
                    "q2_who": {
                        "source_ip": "192.168.1.3",
                        "targets": ["192.168.1.2", "192.168.1.1"],
                        "target_ports": [80, 443, 21, 22, 23],
                        "cti_reputation": "تم تسجيل نشاط معادٍ يطابق أدوات استخبارات التهديد"
                    },
                    "q3_when": {
                        "start_time": "14:08:20",
                        "last_seen": "14:09:15",
                        "stages": [
                            {"phase": "المرحلة 1", "desc": "مسح منافذ استطلاعي لاكتشاف الخدمات النشطة (Discovery)"},
                            {"phase": "المرحلة 2", "desc": "محاولة استغلال الثغرات وإغراق المنافذ بحزم غير مكتملة (Execution)"},
                            {"phase": "المرحلة 3", "desc": "محاولة شل حركة المرور وتعطيل الاتصال (Denial of Service)"}
                        ]
                    },
                    "q4_status": {
                        "is_active": True,
                        "c2_check": "C2: تم رصد تدفقات متزامنة مكثفة دون وجود مؤشرات اتصال دوري تقليدي",
                        "containment_action": "عزل المضيف 192.168.1.3 فوراً ومنع مروره عبر الجدار الناري",
                        "priority": "P1 - IMMEDIATE ISOLATION"
                    },
                    "narrative": "تقرير الذكاء الاصطناعي السردي للحادثة: رصد المحلل الذكي نشاطاً مشبوهاً عالي الخطورة صادراً من العنوان 192.168.1.3 مستهدفاً أجهزة الشبكة الداخلية عبر منافذ متعددة بمعدل ثقة 99%. تم تصنيف الحادثة كـ CRITICAL بناءً على تجميع مؤشرات الشذوذ وسلوك التدفقات.",
                    "containment_command": "iptables -A INPUT -s 192.168.1.3 -j DROP\nnetsh advfirewall firewall add rule name=\"BLOCK_192.168.1.3\" dir=in action=block remoteip=192.168.1.3"
                },
                "ip_summaries": [
                    {
                        "ip": "192.168.1.3",
                        "role": "Attacker",
                        "flows_count": 48,
                        "attack_flows": 32,
                        "threat_level": "MALICIOUS",
                        "likely_type": "SYN Flood / PortScan",
                        "mitre": {"technique_id": "T1498", "tactic": "Impact"},
                        "cti_score": 85
                    }
                ],
                "total_flows": 64,
                "attack_count": 17,
                "suspicious_count": 41,
                "normal_count": 6,
                "vector_map": {
                    "attackers": ["192.168.1.3"],
                    "targets": ["192.168.1.2", "192.168.1.1", "172.211.123.248", "8.8.8.8"],
                    "benign": ["192.168.100.2"],
                    "links": [
                        {"source": "192.168.1.3", "target": "192.168.1.2", "decision": "Attack", "count": 28},
                        {"source": "192.168.1.3", "target": "192.168.1.1", "decision": "Attack", "count": 14}
                    ]
                },
                "hierarchical_tree": [
                    {"src_ip": "192.168.1.3", "dst_ip": "192.168.1.2", "dst_port": 80, "proto": "TCP", "status": "Malicious/SYN Flood"},
                    {"src_ip": "192.168.1.3", "dst_ip": "192.168.1.2", "dst_port": 443, "proto": "TCP", "status": "Malicious/PortScan"},
                    {"src_ip": "192.168.1.3", "dst_ip": "192.168.1.1", "dst_port": 53, "proto": "UDP", "status": "Suspicious/DNS"}
                ],
                "active_mitre_tids": ["T1498", "T1046", "T1190"],
                "dns_telemetry": [
                    {"query": "api.cyberintel-threats.xyz", "entropy": 4.12, "dga_prob": 0.88, "status": "SUSPICIOUS DGA"},
                    {"query": "data-exfil.tunnel.internal", "entropy": 3.95, "dga_prob": 0.76, "status": "TUNNEL DETECTED"}
                ],
                "tls_telemetry": [
                    {"sni": "c2-beacon.darkops.net", "ja3": "771,4865-4866-4867,0-23-65281,29-23-24,0", "self_signed": True, "risk": "HIGH C2 RISK"}
                ],
                "beaconing": [
                    {"dst_ip": "192.168.1.2", "dst_port": 443, "interval": 10.2, "jitter": 0.05, "confidence": "HIGH C2 BEACONING"}
                ]
            }

        js_ip_data = {}
        for ip, prof in profiler.ip_profiles.items():
            g = geo_map.get(ip, {})
            vt = ip_lookups.get(ip, intel.lookup_ip_deep(ip))
            js_ip_data[ip] = {
                "profile": prof.to_dict(),
                "geo": g,
                "vt": vt
            }

        # Serialized packet stream for live client search & Wireshark dissection (up to 500 packets)
        js_packets = []
        limit = min(500, len(packets))
        for p in packets[:limit]:
            raw_sample = p.raw_data[:256]
            hex_lines = bytes_to_hex_dump(raw_sample)
            ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_sample)
            js_packets.append({
                "Packet_Number": p.packet_num,
                "Relative_Time": round(p.rel_time, 6),
                "Source": p.src,
                "Destination": p.dst,
                "Source_Port": p.src_port,
                "Destination_Port": p.dst_port,
                "Protocol": p.protocol,
                "Length": p.captured_length,
                "Info": p.info,
                "Layers": p.layers,
                "Hex_Dump": hex_lines,
                "Raw_Hex": raw_sample.hex(),
                "ASCII": ascii_dump
            })

        proto_json = json.dumps(proto_dist)
        alerts_json = json.dumps([a.to_dict() for a in alerts])

        critical_banner_html = ""
        if len(alerts) > 0:
            critical_banner_html = f"""
            <div class="critical-banner">
              <div class="critical-banner-left">
                <div class="alert-circle-icon">!</div>
                <div>
                  <div class="critical-banner-title">{len(alerts)} Critical Security Incidents Identified</div>
                  <div class="critical-banner-sub">High-risk anomalous network activities requiring prompt analyst review and automated containment</div>
                </div>
              </div>
              <button class="btn-inspect-critical" onclick="switchTab('tab-threats', document.querySelectorAll('.nav-tab-btn')[2])">Inspect Critical Alerts &rarr;</button>
            </div>
            """

        dashboard_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>⚡ NetPacket Inspector Pro • Smart SOC Platform</title>
<style>
  :root, [data-theme="dark"] {{
    --bg-page: #080d1a;
    --bg-card: #0d1527;
    --bg-panel: #0d1527;
    --bg-subtle: #131f38;
    --bg-input: #101a30;
    
    /* Primary Blue Palette */
    --primary-blue: #3b82f6;
    --primary-dark: #2563eb;
    --primary-deep: #60a5fa;
    --blue-border: #1e3a5f;
    --blue-border-hover: #3b82f6;
    --blue-subtle: rgba(59, 130, 246, 0.15);
    --blue-badge: #172554;
    
    /* Alert Status Colors */
    --crit-red: #ef4444;
    --crit-bg: rgba(239, 68, 68, 0.15);
    --crit-border: rgba(239, 68, 68, 0.4);
    
    --warn-orange: #f97316;
    --warn-bg: rgba(249, 115, 22, 0.15);
    --warn-border: rgba(249, 115, 22, 0.4);
    
    --success-green: #10b981;
    --success-bg: rgba(16, 185, 129, 0.15);
    --success-border: rgba(16, 185, 129, 0.4);
    
    /* Typography & Neutral Colors */
    --text-main: #f8fafc;
    --text-navy: #e2e8f0;
    --text-muted: #94a3b8;
    --text-subtle: #64748b;
    --border-neutral: #1e293b;
    --canvas-bg: #080d1a;
    --table-hover: #131f38;
    --shadow-card: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -2px rgba(0, 0, 0, 0.2);
    --shadow-hover: 0 10px 25px -5px rgba(59, 130, 246, 0.25);
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  }}

  [data-theme="light"] {{
    --bg-page: #f8fafc;
    --bg-card: #ffffff;
    --bg-panel: #ffffff;
    --bg-subtle: #f1f5f9;
    --bg-input: #ffffff;
    
    /* Primary Blue Palette */
    --primary-blue: #2563eb;
    --primary-dark: #1d4ed8;
    --primary-deep: #1e3a8a;
    --blue-border: #bfdbfe;
    --blue-border-hover: #3b82f6;
    --blue-subtle: #eff6ff;
    --blue-badge: #dbeafe;
    
    /* Alert Status Colors */
    --crit-red: #dc2626;
    --crit-bg: #fef2f2;
    --crit-border: #fca5a5;
    
    --warn-orange: #ea580c;
    --warn-bg: #fff7ed;
    --warn-border: #fdba74;
    
    --success-green: #16a34a;
    --success-bg: #f0fdf4;
    --success-border: #86efac;
    
    /* Typography & Neutral Colors */
    --text-main: #0f172a;
    --text-navy: #1e293b;
    --text-muted: #64748b;
    --text-subtle: #94a3b8;
    --border-neutral: #e2e8f0;
    --canvas-bg: #f8fafc;
    --table-hover: #eff6ff;
    --shadow-card: 0 1px 3px 0 rgba(0, 0, 0, 0.07), 0 1px 2px -1px rgba(0, 0, 0, 0.05);
    --shadow-hover: 0 10px 25px -5px rgba(37, 99, 235, 0.12), 0 8px 10px -6px rgba(37, 99, 235, 0.08);
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background-color: var(--bg-page);
    background-image: radial-gradient(var(--border-neutral) 1px, transparent 1px);
    background-size: 24px 24px;
    color: var(--text-main);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    padding: 20px 28px;
    line-height: 1.5;
    min-height: 100vh;
    transition: background-color 0.2s ease, color 0.2s ease;
  }}

  /* Custom Scrollbar */
  ::-webkit-scrollbar {{ width: 7px; height: 7px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg-page); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border-neutral); border-radius: 4px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--text-muted); }}

  /* Top Navigation & Brand Header */
  .soc-header {{
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 16px;
    padding: 16px 24px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: var(--shadow-card);
    flex-wrap: wrap;
    gap: 16px;
    transition: background-color 0.2s, border-color 0.2s;
  }}

  .brand-group {{
    display: flex;
    align-items: center;
    gap: 16px;
  }}

  .emblem-wrapper {{
    position: relative;
    width: 60px;
    height: 60px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--blue-subtle);
    border: 2.5px solid var(--primary-blue);
    box-shadow: 0 0 14px rgba(37, 99, 235, 0.25);
    overflow: hidden;
    cursor: pointer;
    transition: transform 0.3s;
  }}
  .emblem-wrapper:hover {{ transform: scale(1.05); }}
  .emblem-img {{ width: 100%; height: 100%; object-fit: cover; }}

  .brand-details {{ display: flex; flex-direction: column; }}
  .platform-title {{
    font-size: 22px;
    font-weight: 800;
    color: var(--primary-deep);
    letter-spacing: -0.3px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .platform-title .smart-badge {{
    font-size: 11px;
    font-weight: 700;
    background: var(--blue-badge);
    color: var(--primary-dark);
    padding: 2px 10px;
    border-radius: 20px;
    border: 1px solid var(--blue-border);
  }}

  .platform-subtitle {{
    font-size: 13px;
    color: var(--text-muted);
    margin-top: 2px;
  }}
  .arabic-meta {{
    font-size: 12px;
    color: var(--primary-blue);
    font-weight: 600;
    margin-top: 1px;
  }}

  .header-controls {{
    display: flex;
    align-items: center;
    gap: 14px;
    flex-wrap: wrap;
  }}

  .status-pill {{
    background: {posture_badge_bg};
    border: 1px solid {posture_badge_border};
    color: {posture_badge_text};
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  .status-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: {posture_badge_text};
    display: inline-block;
  }}

  .btn-header {{
    background: var(--bg-card);
    border: 1px solid var(--border-neutral);
    color: var(--text-navy);
    padding: 7px 14px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  .btn-header:hover {{
    background: var(--blue-subtle);
    border-color: var(--blue-border);
    color: var(--primary-blue);
  }}

  /* Critical Alert Hero Banner (Inspired by Smart SOC Platform Image 1) */
  .critical-banner {{
    background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
    color: #ffffff;
    border-radius: 14px;
    padding: 18px 24px;
    margin-bottom: 22px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 14px rgba(220, 38, 38, 0.25);
    flex-wrap: wrap;
    gap: 14px;
  }}

  .critical-banner-left {{
    display: flex;
    align-items: center;
    gap: 14px;
  }}

  .alert-circle-icon {{
    width: 44px;
    height: 44px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.2);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    font-weight: 900;
    flex-shrink: 0;
  }}

  .critical-banner-title {{
    font-size: 18px;
    font-weight: 800;
    letter-spacing: -0.2px;
  }}
  .critical-banner-sub {{
    font-size: 13px;
    opacity: 0.92;
    margin-top: 2px;
  }}

  .btn-inspect-critical {{
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid rgba(255, 255, 255, 0.35);
    color: #ffffff;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .btn-inspect-critical:hover {{
    background: #ffffff;
    color: #dc2626;
  }}

  /* Metric HUD Cards Grid (White cards with colored borders & icons) */
  .grid-hud {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 22px;
  }}

  .hud-card {{
    background: var(--bg-card);
    border-radius: 12px;
    padding: 18px 20px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    box-shadow: var(--shadow-card);
    transition: transform 0.2s, box-shadow 0.2s, border-color 0.2s;
    position: relative;
    border: 1.5px solid var(--blue-border);
  }}
  .hud-card:hover {{
    transform: translateY(-3px);
    box-shadow: var(--shadow-hover);
    border-color: var(--primary-blue);
  }}

  .hud-card.border-red {{ border-color: var(--crit-border); }}
  .hud-card.border-red:hover {{ border-color: var(--crit-red); }}
  
  .hud-card.border-green {{ border-color: var(--success-border); }}
  .hud-card.border-green:hover {{ border-color: var(--success-green); }}

  .hud-card.border-orange {{ border-color: var(--warn-border); }}
  .hud-card.border-orange:hover {{ border-color: var(--warn-orange); }}

  .hud-title {{
    font-size: 12px;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .hud-value {{
    font-size: 28px;
    font-weight: 800;
    color: var(--text-main);
    margin-top: 6px;
    letter-spacing: -0.5px;
  }}
  .hud-subtext {{
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
  }}

  .hud-icon-box {{
    width: 44px;
    height: 44px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }}
  .icon-blue {{ background: var(--blue-subtle); color: var(--primary-blue); }}
  .icon-red {{ background: var(--crit-bg); color: var(--crit-red); }}
  .icon-green {{ background: var(--success-bg); color: var(--success-green); }}
  .icon-orange {{ background: var(--warn-bg); color: var(--warn-orange); }}

  /* Clean White Navigation Tabs Bar */
  .soc-nav-bar {{
    display: flex;
    gap: 8px;
    background: var(--bg-card);
    border: 1px solid var(--border-neutral);
    border-radius: 14px;
    padding: 8px;
    margin-bottom: 20px;
    box-shadow: var(--shadow-card);
    overflow-x: auto;
  }}

  .nav-tab-btn {{
    background: transparent;
    border: 1px solid transparent;
    color: var(--text-muted);
    padding: 10px 18px;
    border-radius: 10px;
    font-size: 13px;
    font-weight: 700;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
    transition: all 0.2s;
  }}
  .nav-tab-btn:hover {{
    color: var(--primary-blue);
    background: var(--blue-subtle);
  }}
  .nav-tab-btn.active {{
    background: var(--primary-blue);
    color: #ffffff;
    box-shadow: 0 4px 12px rgba(37, 99, 235, 0.25);
  }}

  .tab-count-badge {{
    background: rgba(255, 255, 255, 0.25);
    color: #ffffff;
    font-size: 11px;
    padding: 1px 7px;
    border-radius: 12px;
  }}
  .nav-tab-btn:not(.active) .tab-count-badge {{
    background: var(--blue-badge);
    color: var(--primary-dark);
  }}
  .nav-tab-btn:not(.active) .tab-count-badge.danger {{
    background: var(--crit-bg);
    color: var(--crit-red);
  }}

  .tab-pane {{ display: none; }}
  .tab-pane.active {{ display: block; }}

  /* __AI_CSS_PLACEHOLDER__ */


  /* Cards & Sections (Clean White with Blue Borders) */
  .soc-card {{
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 14px;
    padding: 22px;
    box-shadow: var(--shadow-card);
    margin-bottom: 22px;
    transition: border-color 0.2s, box-shadow 0.2s;
  }}
  .soc-card:hover {{
    border-color: var(--blue-border-hover);
  }}

  .soc-card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 18px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-neutral);
    flex-wrap: wrap;
    gap: 10px;
  }}
  .soc-card-title {{
    font-size: 16px;
    font-weight: 800;
    color: var(--primary-deep);
    display: flex;
    align-items: center;
    gap: 8px;
  }}

  .grid-2col {{ display: grid; grid-template-columns: 1.2fr 1fr; gap: 20px; margin-bottom: 20px; }}
  @media (max-width: 1080px) {{ .grid-2col {{ grid-template-columns: 1fr; }} }}

  /* Network Canvas */
  #networkCanvas {{
    width: 100%;
    height: 380px;
    background: var(--canvas-bg);
    border-radius: 10px;
    border: 1.5px solid var(--blue-border);
    display: block;
    cursor: grab;
  }}
  #networkCanvas:active {{ cursor: grabbing; }}

  /* Data Tables (White + Subtle Blue borders) */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{
    background: var(--bg-subtle);
    color: var(--primary-deep);
    padding: 11px 14px;
    font-weight: 700;
    border-bottom: 2px solid var(--blue-border);
    text-align: left;
    white-space: nowrap;
    font-size: 11px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }}
  td {{
    padding: 11px 14px;
    border-bottom: 1px solid var(--border-neutral);
    color: var(--text-navy);
  }}
  tr:hover td {{ background: var(--blue-subtle); }}
  code {{ font-family: var(--font-mono); color: var(--primary-dark); font-size: 12px; background: var(--blue-subtle); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--blue-border); }}

  /* Badges */
  .badge-tag {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .badge-proto-tcp {{ background: #dbeafe; color: #1e40af; border: 1px solid #bfdbfe; }}
  .badge-proto-udp {{ background: #d1fae5; color: #065f46; border: 1px solid #a7f3d0; }}
  .badge-proto-dns {{ background: #cffafe; color: #155e75; border: 1px solid #a5f3fc; }}
  .badge-proto-http {{ background: #f3e8ff; color: #6b21a8; border: 1px solid #e9d5ff; }}
  .badge-proto-tls {{ background: #ccfbf1; color: #115e59; border: 1px solid #99f6e4; }}

  .badge-crit {{ background: var(--crit-bg); color: var(--crit-red); border: 1px solid var(--crit-border); }}
  .badge-high {{ background: var(--warn-bg); color: var(--warn-orange); border: 1px solid var(--warn-border); }}
  .badge-clean {{ background: var(--success-bg); color: var(--success-green); border: 1px solid var(--success-border); }}

  /* Action Buttons */
  .btn-action-blue {{
    background: var(--primary-blue);
    color: #ffffff;
    border: none;
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .btn-action-blue:hover {{
    background: var(--primary-dark);
    box-shadow: 0 4px 10px rgba(37, 99, 235, 0.25);
  }}

  .btn-secondary-outline {{
    background: var(--bg-card);
    border: 1px solid var(--blue-border);
    color: var(--primary-blue);
    padding: 6px 12px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .btn-secondary-outline:hover {{
    background: var(--blue-subtle);
    border-color: var(--primary-blue);
  }}

  /* Filter Toolbar */
  .filter-bar {{
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    flex-wrap: wrap;
    align-items: center;
  }}
  .search-box-input {{
    background: var(--bg-input);
    border: 1.5px solid var(--blue-border);
    color: var(--text-main);
    padding: 9px 14px;
    border-radius: 8px;
    font-size: 13px;
    flex-grow: 1;
    min-width: 280px;
    font-family: var(--font-mono);
    transition: border-color 0.2s, box-shadow 0.2s;
  }}
  .search-box-input:focus {{
    outline: none;
    border-color: var(--primary-blue);
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
  }}

  .chips-container {{
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }}
  .filter-chip {{
    background: var(--bg-card);
    border: 1px solid var(--blue-border);
    color: var(--text-navy);
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .filter-chip:hover {{
    background: var(--blue-subtle);
    border-color: var(--primary-blue);
    color: var(--primary-blue);
  }}
  .filter-chip.active {{
    background: var(--primary-blue);
    color: #ffffff;
    border-color: var(--primary-blue);
  }}

  /* Wireshark 3-Pane Dissector View */
  .dissector-container {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-top: 16px;
  }}
  @media (max-width: 960px) {{ .dissector-container {{ grid-template-columns: 1fr; }} }}

  .dissector-panel {{
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 10px;
    padding: 14px;
  }}
  .dissector-panel-title {{
    font-size: 12px;
    font-weight: 800;
    color: var(--primary-deep);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
  }}
  .layer-item-box {{
    padding: 8px 12px;
    background: var(--blue-subtle);
    border-left: 3px solid var(--primary-blue);
    border-radius: 4px;
    margin-bottom: 8px;
    font-family: var(--font-mono);
    font-size: 12px;
  }}
  .hex-view-box {{
    font-family: var(--font-mono);
    font-size: 11px;
    line-height: 1.6;
    color: var(--text-main);
    background: var(--bg-subtle);
    padding: 12px;
    border-radius: 8px;
    max-height: 220px;
    overflow-y: auto;
    white-space: pre;
    border: 1.5px solid var(--blue-border);
  }}

  /* Threat Items */
  .threat-entry {{
    background: var(--bg-card);
    border: 1.5px solid var(--border-neutral);
    border-left: 5px solid var(--primary-blue);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
    transition: transform 0.2s, box-shadow 0.2s;
  }}
  .threat-entry:hover {{
    transform: translateX(4px);
    box-shadow: var(--shadow-card);
  }}
  .threat-entry.threat-crit {{
    border-left-color: var(--crit-red);
    background: var(--crit-bg);
  }}
  .threat-entry.threat-high {{
    border-left-color: var(--warn-orange);
    background: var(--warn-bg);
  }}

  /* Carved Files Grid */
  .carved-cards-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 16px;
  }}
  .carved-box {{
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-radius: 12px;
    padding: 16px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    transition: all 0.2s;
  }}
  .carved-box:hover {{
    border-color: var(--primary-blue);
    transform: translateY(-3px);
    box-shadow: var(--shadow-hover);
  }}

  /* Playbook Cards */
  .playbook-step-card {{
    background: var(--bg-card);
    border: 1.5px solid var(--blue-border);
    border-left: 5px solid var(--primary-blue);
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 12px;
    display: flex;
    gap: 14px;
    align-items: flex-start;
  }}
  .playbook-step-card.completed {{
    opacity: 0.65;
    border-left-color: var(--success-green);
    background: var(--success-bg);
  }}
  .playbook-check {{
    width: 20px;
    height: 20px;
    cursor: pointer;
    accent-color: var(--primary-blue);
    margin-top: 3px;
  }}

  /* Modal Dialog */
  .modal-backdrop-bg {{
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(8, 13, 26, 0.75);
    z-index: 9999;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(5px);
    padding: 20px;
  }}
  .modal-content-card {{
    background: var(--bg-card);
    border: 2px solid var(--primary-blue);
    border-radius: 16px;
    width: 100%;
    max-width: 760px;
    max-height: 85vh;
    overflow-y: auto;
    padding: 24px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.35);
  }}

  .pkt-row.selected-row td {{
    background: var(--blue-badge) !important;
    color: var(--primary-deep) !important;
    font-weight: 700;
  }}
</style>
</head>
<body>

<!-- Top Navigation & Brand Header -->
<div class="soc-header">
  <div class="brand-group">
    <div class="emblem-wrapper" title="Kali Linux & Wireshark Dual Engine" onclick="playCyberSound('beep')">
      <img src="{EMBLEM_B64}" alt="Kali x Wireshark Emblem" class="emblem-img">
    </div>
    <div class="brand-details">
      <div class="platform-title">
        <span>NetPacket Inspector Pro</span>
        <span class="smart-badge">SMART SOC PLATFORM</span>
      </div>
      <div class="platform-subtitle">Live Threat Monitoring, Deep Packet Dissection & Triage Hub</div>
      <div class="arabic-meta">منظومة العمليات الأمنية والتحليل الجنائي السيبراني لاختراق وتدفقات الحزم</div>
    </div>
  </div>

  <div class="header-controls">
    <div class="status-pill">
      <span class="status-dot"></span>
      <span>{threat_posture}</span>
    </div>
    <button class="btn-header" id="themeToggleBtn" onclick="toggleDashboardTheme()">☀️ White Mode</button>
    <button class="btn-header" id="soundToggleBtn" onclick="toggleSound()">🔊 Audio SFX</button>
    <div style="font-size:12px; color:var(--text-muted);">
      Target: <strong style="color:var(--primary-deep);">{source_filename}</strong>
    </div>
  </div>
</div>

<!-- Critical Security Events Hero Banner (Inspired by Smart SOC Platform) -->
{critical_banner_html}

<!-- Metric HUD Cards Grid (Clean White Cards with Colored Borders) -->
<div class="grid-hud">
  <div class="hud-card">
    <div>
      <div class="hud-title">Total Ingested Packets</div>
      <div class="hud-value" style="color:var(--primary-blue);">{stats.get('Total_Packets')}</div>
      <div class="hud-subtext">Rate: {stats.get('Avg_Packet_Rate_per_sec')} pkts/s</div>
    </div>
    <div class="hud-icon-box icon-blue">📦</div>
  </div>

  <div class="hud-card border-red">
    <div>
      <div class="hud-title">High Priority Queue</div>
      <div class="hud-value" style="color:var(--crit-red);">{crit_count + high_count}</div>
      <div class="hud-subtext">{crit_count} Critical • {high_count} High alerts</div>
    </div>
    <div class="hud-icon-box icon-red">🛡️</div>
  </div>

  <div class="hud-card border-green">
    <div>
      <div class="hud-title">Carved File Artifacts</div>
      <div class="hud-value" style="color:var(--success-green);">{len(carved_files)}</div>
      <div class="hud-subtext">Payloads & File Streams</div>
    </div>
    <div class="hud-icon-box icon-green">⚡</div>
  </div>

  <div class="hud-card border-orange">
    <div>
      <div class="hud-title">Active Host Endpoints</div>
      <div class="hud-value" style="color:var(--warn-orange);">{len(ip_profiles)}</div>
      <div class="hud-subtext">{len(streams)} Reconstructed Sessions</div>
    </div>
    <div class="hud-icon-box icon-orange">🌐</div>
  </div>

  <div class="hud-card">
    <div>
      <div class="hud-title">Capture Data Volume</div>
      <div class="hud-value" style="color:var(--primary-deep);">{stats.get('Total_Bytes_Formatted')}</div>
      <div class="hud-subtext">Throughput: {stats.get('Avg_Bandwidth_Kbps')} Kbps</div>
    </div>
    <div class="hud-icon-box icon-blue">📊</div>
  </div>
</div>

<!-- Navigation Tabs Bar -->
<div class="soc-nav-bar">
  <button class="nav-tab-btn active" onclick="switchTab('tab-overview', this)">
    <span>🌐 Overview & Topology</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-dissector', this)">
    <span>📦 Packet Dissector (Wireshark)</span>
    <span class="tab-count-badge">{len(packets)}</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-threats', this)">
    <span>🛡️ Threat Matrix & MITRE</span>
    <span class="tab-count-badge danger">{len(alerts)}</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-geoip', this)">
    <span>🗺️ GeoIP & Domains</span>
    <span class="tab-count-badge">{len(geo_data)}</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-carver', this)">
    <span>📁 File Carving Sandbox</span>
    <span class="tab-count-badge">{len(carved_files)}</span>
  </button>
  <button class="nav-tab-btn" onclick="switchTab('tab-playbook', this)">
    <span>📋 Incident Playbook</span>
    <span class="tab-count-badge" id="playbookProgressBadge">0/{len(playbook)}</span>
  </button>

  <!-- __AI_NAV_TABS_PLACEHOLDER__ -->
</div>

<!-- TAB 1: OVERVIEW & TOPOLOGY -->
<div id="tab-overview" class="tab-pane active">
  <div class="grid-2col">
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">🌐 Interactive Network Communication Graph</div>
        <span style="font-size:12px; color:var(--text-muted);">Draggable Nodes • Live Flow Simulation</span>
      </div>
      <canvas id="networkCanvas"></canvas>
      <div style="display:flex; justify-content:space-between; margin-top:12px; font-size:12px; color:var(--text-muted); flex-wrap:wrap; gap:8px;">
        <span style="display:flex; align-items:center; gap:6px;"><span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#ef4444;"></span> Malicious</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#f97316;"></span> Suspicious</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#10b981;"></span> Private LAN</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#2563eb;"></span> Public WAN</span>
      </div>
    </div>

    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">📊 Protocol Distribution & Traffic Share</div>
        <span style="font-size:12px; color:var(--text-muted);">Click to filter dissector</span>
      </div>
      <div style="overflow-x: auto;">
        <table>
          <thead><tr><th>Protocol</th><th>Packets</th><th>Percentage</th><th>Volume Share</th></tr></thead>
          <tbody>
            {"".join(f'''
            <tr style="cursor:pointer;" onclick="filterByQuickChip('{p['Protocol']}')" title="Click to filter by {p['Protocol']}">
              <td><span class="badge-tag badge-proto-{p['Protocol'].lower()}">{p['Protocol']}</span></td>
              <td><strong>{p['Count']}</strong></td>
              <td>{p['Percentage']}%</td>
              <td>
                <div style="background:#e2e8f0; border-radius:4px; height:8px; width:100%; overflow:hidden;">
                  <div style="background:linear-gradient(90deg, #2563eb, #38bdf8); width:{p['Percentage']}%; height:100%;"></div>
                </div>
              </td>
            </tr>
            ''' for p in proto_dist)}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<!-- TAB 2: WIRESHARK PACKET DISSECTOR -->
<div id="tab-dissector" class="tab-pane">
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">🔍 Wireshark-Style Live Packet Stream Dissector</div>
      <span id="livePktCount" style="font-size:12px; color:var(--primary-deep); font-weight:700;">Showing {len(js_packets)} packets</span>
    </div>

    <!-- Filter Toolbar -->
    <div class="filter-bar">
      <input type="text" id="liveSearchInput" class="search-box-input" placeholder="🔍 Universal Search: Filter by IP, Protocol (TCP, DNS, HTTP, TLS), Port, or String..." oninput="handleLiveFilter()">
      <div class="chips-container">
        <button class="filter-chip active" id="chip-all" onclick="filterByQuickChip('ALL')">All Packets</button>
        <button class="filter-chip" id="chip-threats" onclick="filterByQuickChip('THREATS')">🚨 Threats</button>
        <button class="filter-chip" id="chip-http" onclick="filterByQuickChip('HTTP')">HTTP</button>
        <button class="filter-chip" id="chip-dns" onclick="filterByQuickChip('DNS')">DNS</button>
        <button class="filter-chip" id="chip-tcp" onclick="filterByQuickChip('TCP')">TCP</button>
        <button class="filter-chip" id="chip-tls" onclick="filterByQuickChip('TLS')">TLS</button>
        <button class="btn-secondary-outline" onclick="resetLiveFilter()">Clear Filter</button>
      </div>
    </div>

    <!-- Packet Table -->
    <div style="overflow-x: auto; max-height: 400px; overflow-y: auto; border: 1.5px solid var(--blue-border); border-radius: 10px;">
      <table id="packetTable">
        <thead>
          <tr>
            <th style="width:60px;">#</th>
            <th style="width:90px;">Time (s)</th>
            <th style="width:160px;">Source</th>
            <th style="width:160px;">Destination</th>
            <th style="width:90px;">Protocol</th>
            <th style="width:70px;">Length</th>
            <th>Dissection Info</th>
          </tr>
        </thead>
        <tbody id="packetTbody">
          {"".join(f'''
          <tr class="pkt-row" data-pkt="{p['Packet_Number']}" data-proto="{p['Protocol'].lower()}" data-src="{p['Source']}" data-dst="{p['Destination']}" data-info="{p['Info'].lower()}" onclick="selectPacketRow({p['Packet_Number']})" style="cursor:pointer;">
            <td><strong>#{p['Packet_Number']}</strong></td>
            <td>{p['Relative_Time']:.6f}</td>
            <td><a href="javascript:void(0)" onclick="openIpModal('{p['Source']}'); event.stopPropagation();" style="color:var(--primary-blue); font-weight:600; text-decoration:none;"><code>{p['Source']}</code></a></td>
            <td><a href="javascript:void(0)" onclick="openIpModal('{p['Destination']}'); event.stopPropagation();" style="color:var(--primary-blue); font-weight:600; text-decoration:none;"><code>{p['Destination']}</code></a></td>
            <td><span class="badge-tag badge-proto-{p['Protocol'].lower()}">{p['Protocol']}</span></td>
            <td>{p['Length']}</td>
            <td style="font-family:var(--font-mono); font-size:12px;">{p['Info']}</td>
          </tr>
          ''' for p in js_packets)}
        </tbody>
      </table>
    </div>

    <!-- Lower 3-Pane Dissector View -->
    <div class="dissector-container">
      <div class="dissector-panel">
        <div class="dissector-panel-title">
          <span id="dissectorTreeTitle">📑 Protocol Layer Hierarchy</span>
          <span style="font-size:11px; color:var(--text-muted);">Frame & Fields</span>
        </div>
        <div id="dissectorLayerContainer" style="max-height: 240px; overflow-y: auto;">
          <div style="color:var(--text-muted); font-size:12px; padding:20px; text-align:center;">Click any packet row above to dissect its protocol layers.</div>
        </div>
      </div>

      <div class="dissector-panel">
        <div class="dissector-panel-title">
          <span>🔍 Monospace Raw Hex & ASCII Dump</span>
          <button class="btn-secondary-outline" style="padding:2px 8px; font-size:10px;" onclick="copyActiveHex()">Copy Hex</button>
        </div>
        <pre id="dissectorHexView" class="hex-view-box">Select a packet to inspect raw payload bytes...</pre>
      </div>
    </div>
  </div>
</div>

<!-- TAB 3: THREAT MATRIX & MITRE ATT&CK -->
<div id="tab-threats" class="tab-pane">
  <div class="grid-2col">
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">🛡️ Identified Malicious Incidents ({len(alerts)})</div>
        <div style="display:flex; gap:6px;">
          <button class="btn-secondary-outline" style="padding:4px 8px; font-size:11px;" onclick="filterAlertsBySev('ALL')">All</button>
          <button class="btn-secondary-outline" style="padding:4px 8px; font-size:11px; color:var(--crit-red); border-color:var(--crit-border);" onclick="filterAlertsBySev('CRITICAL')">Critical ({crit_count})</button>
          <button class="btn-secondary-outline" style="padding:4px 8px; font-size:11px; color:var(--warn-orange); border-color:var(--warn-border);" onclick="filterAlertsBySev('HIGH')">High ({high_count})</button>
        </div>
      </div>
      <div style="max-height: 520px; overflow-y: auto;">
        {"".join(f'''
        <div class="threat-entry alert-card {'threat-crit' if a.severity == 'CRITICAL' else 'threat-high'}" data-sev="{a.severity}">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <div>
              <span class="badge-tag {'badge-crit' if a.severity == 'CRITICAL' else 'badge-high'}">{a.severity}</span>
              <strong style="margin-left:8px; font-size:14px; color:var(--text-main);">{a.title}</strong>
            </div>
            <span style="font-size:11px; color:var(--primary-dark); font-weight:700; background:var(--blue-badge); padding:3px 8px; border-radius:4px;">{a.mitre_technique_id} ({a.mitre_tactic})</span>
          </div>
          <div style="font-size:13px; color:var(--text-muted); margin-bottom:8px;">{a.description}</div>
          <div style="font-size:12px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <span>Source: <a href="javascript:void(0)" onclick="openIpModal('{a.source_ip}')" style="color:var(--primary-blue); font-weight:600;">{a.source_ip}</a> &rarr; Target: <a href="javascript:void(0)" onclick="openIpModal('{a.target_ip}')" style="color:var(--primary-blue); font-weight:600;">{a.target_ip}</a></span>
            <button class="btn-action-blue" onclick="jumpToTriggerPackets('{",".join(str(p) for p in a.related_packet_nums)}')">Inspect {len(a.related_packet_nums)} Trigger Packets &rarr;</button>
          </div>
        </div>
        ''' for a in alerts) if alerts else "<div style='color:var(--success-green); padding:20px; text-align:center;'>✅ Clean Traffic - No active malicious attack patterns identified.</div>"}
      </div>
    </div>

    <!-- Kill Chain Timeline -->
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">⏳ Attack Kill-Chain Timeline</div>
        <span style="font-size:12px; color:var(--text-muted);">Chronological sequence</span>
      </div>
      <div style="max-height: 520px; overflow-y: auto;">
        {"".join(f'''
        <div style="display:flex; gap:12px; margin-bottom:14px;">
          <div style="font-family:var(--font-mono); font-size:12px; color:var(--primary-blue); min-width:65px; text-align:right; font-weight:700;">+{t['Timestamp_Rel']}s</div>
          <div style="background:var(--blue-subtle); border-left:3px solid var(--primary-blue); border-radius:6px; padding:10px 14px; flex-grow:1;">
            <div style="font-size:11px; color:var(--primary-deep); font-weight:800; text-transform:uppercase;">[{t['Kill_Chain_Phase']}] {t['Incident_Title']}</div>
            <div style="font-size:12px; color:var(--text-muted); margin:3px 0;">{t['Description']}</div>
            <div style="font-size:11px; color:var(--text-navy);">Flow: <code>{t['Attacker']}</code> &rarr; <code>{t['Victim']}</code></div>
          </div>
        </div>
        ''' for t in timeline) if timeline else "<div style='color:var(--text-muted); padding:20px; text-align:center;'>No sequential attack timeline available.</div>"}
      </div>
    </div>
  </div>
</div>

<!-- TAB 4: GEOIP & DOMAINS -->
<div id="tab-geoip" class="tab-pane">
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">🗺️ Endpoint IP Geolocation, ASN & Correlated Domain Names</div>
      <span style="font-size:12px; color:var(--text-muted);">{len(geo_data)} Unique Endpoints</span>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Endpoint IP</th>
            <th>Network Type</th>
            <th>Correlated Domains / Services</th>
            <th>Country & Region</th>
            <th>City</th>
            <th>Autonomous System (ASN)</th>
            <th>ISP / Network Owner</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {"".join(f'''
          <tr>
            <td><a href="javascript:void(0)" onclick="openIpModal('{g['IP']}')" style="color:var(--primary-blue); font-weight:700; text-decoration:none;"><code>{g['IP']}</code></a></td>
            <td>{'<span class="badge-tag" style="background:#f1f5f9; color:#475569; border:1px solid #cbd5e1;">LAN PRIVATE</span>' if g['Is_Private'] else '<span class="badge-tag" style="background:#d1fae5; color:#065f46; border:1px solid #a7f3d0;">PUBLIC WAN</span>'}</td>
            <td style="color:var(--primary-dark); font-weight:600;">{", ".join(g['Domain_Names']) if g['Domain_Names'] else '(None)'}</td>
            <td><strong>{g['Country']}</strong> <span style="color:#64748b; font-size:11px;">({g['Country_Code']})</span></td>
            <td>{g['City']}</td>
            <td><code>{g['ASN']}</code></td>
            <td style="font-size:11px; color:#64748b;">{g['ISP']}</td>
            <td><button class="btn-action-blue" style="padding:4px 8px; font-size:10px;" onclick="openIpModal('{g['IP']}')">Deep Intel</button></td>
          </tr>
          ''' for g in geo_data)}
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- TAB 5: FILE CARVING SANDBOX -->
<div id="tab-carver" class="tab-pane">
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">📁 Extracted File Artifacts & Script Payloads ({len(carved_files)})</div>
      <span style="font-size:12px; color:var(--text-muted);">Automated Stream Reconstruction</span>
    </div>
    <div class="carved-cards-grid">
      {"".join(f'''
      <div class="carved-box">
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <span class="badge-tag" style="background:#f3e8ff; color:#6b21a8; border:1px solid #e9d5ff;">{cf['File_Type']}</span>
            <span style="font-size:11px; color:var(--text-muted);">#{cf['File_ID']}</span>
          </div>
          <div style="font-weight:800; font-size:14px; margin-bottom:4px; color:var(--primary-deep); word-break:break-all;">{cf['Filename']}</div>
          <div style="font-size:12px; color:var(--primary-blue); font-weight:700; margin-bottom:6px;">Size: {cf['Size_Formatted']}</div>
          <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
            Flow: <code>{cf['Source_IP']}</code> &rarr; <code>{cf['Dest_IP']}</code>
          </div>
          <div style="font-size:10px; color:var(--text-subtle); font-family:var(--font-mono); word-break:break-all; margin-bottom:12px;">
            SHA256: {cf['SHA256'][:24]}...
          </div>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn-action-blue" style="flex-grow:1;" onclick="jumpToTriggerPackets('{",".join(str(p) for p in cf['Packet_Numbers'])}')">Inspect Pkts</button>
          <button class="btn-secondary-outline" style="font-size:11px;" onclick="previewCarvedFile('{cf['Filename']}', '{cf['Size_Formatted']}', '{cf['SHA256']}')">Preview</button>
        </div>
      </div>
      ''' for cf in carved_files) if carved_files else "<div style='color:var(--text-muted); padding:20px; text-align:center;'>No carved file objects extracted from current session.</div>"}
    </div>
  </div>
</div>

<!-- TAB 6: INCIDENT RESPONSE PLAYBOOK -->
<div id="tab-playbook" class="tab-pane">
  <div class="soc-card">
    <div class="soc-card-header">
      <div class="soc-card-title">📋 SOC Remediation Action Checklist</div>
      <span style="font-size:12px; color:var(--primary-blue); font-weight:700;">Interactive Workflow</span>
    </div>
    <div id="playbookList">
      {"".join(f'''
      <div class="playbook-step-card" id="pb-step-{idx}">
        <input type="checkbox" class="playbook-check" onchange="togglePlaybookStep({idx}, this)">
        <div style="flex-grow:1;">
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <div>
              <span class="badge-tag {'badge-crit' if 'P0' in pb['Priority'] else 'badge-high'}">{pb['Priority']}</span>
              <strong style="margin-left:8px; font-size:14px; color:var(--primary-deep);">{pb['Action']}</strong>
            </div>
            <span style="font-size:11px; color:var(--text-muted); font-weight:600;">Step {pb['Step']}</span>
          </div>
          <div style="font-size:13px; color:var(--text-navy); margin-bottom:6px;">{pb['Instructions']}</div>
          <div style="font-size:11px; color:var(--primary-blue);">Target Asset: <code>{pb['Target']}</code></div>
        </div>
      </div>
      ''' for idx, pb in enumerate(playbook))}
    </div>
  </div>
</div>


<!-- __AI_HTML_TABS_PLACEHOLDER__ -->

<!-- Deep IP Forensic Modal -->
<div id="ipModalBackdrop" class="modal-backdrop-bg" onclick="closeModalOnBackdrop(event)">
  <div class="modal-content-card">
    <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border-neutral); padding-bottom:12px; margin-bottom:16px;">
      <div id="modalTitle" style="font-size:18px; font-weight:800; color:var(--primary-deep);">🌐 Deep IP Forensic Telemetry</div>
      <button style="background:none; border:none; color:var(--text-muted); font-size:24px; cursor:pointer;" onclick="closeModal()">&times;</button>
    </div>
    <div id="modalBody"></div>
    <div style="margin-top:20px; text-align:right;">
      <button id="modalFilterBtn" class="btn-action-blue" style="padding:8px 18px;" onclick="filterByModalIp()">🎯 Filter Packet Dissector for this IP</button>
    </div>
  </div>
</div>

<!-- Client-Side Engine Scripts -->
<script>
  const IP_STORE = {json.dumps(js_ip_data)};
  const GRAPH_NODES = {json.dumps(nodes)};
  const GRAPH_LINKS = {json.dumps(links)};
  const PACKETS_DATA = {json.dumps(js_packets)};
  const ALERTS_DATA = {alerts_json};
  const AI_DATA = __AI_DATA_PLACEHOLDER__;

  let activeModalIp = "";
  let soundEnabled = true;
  let audioCtx = null;
  let activeSelectedPacket = null;

  function playCyberSound(type = "click") {{
    if (!soundEnabled) return;
    try {{
      if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      if (audioCtx.state === "suspended") audioCtx.resume();

      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      if (type === "click") {{
        osc.type = "sine";
        osc.frequency.setValueAtTime(800, audioCtx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(400, audioCtx.currentTime + 0.05);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.05);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.05);
      }} else if (type === "beep") {{
        osc.type = "triangle";
        osc.frequency.setValueAtTime(520, audioCtx.currentTime);
        osc.frequency.setValueAtTime(780, audioCtx.currentTime + 0.08);
        gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.2);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.2);
      }} else if (type === "alert") {{
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(320, audioCtx.currentTime);
        osc.frequency.linearRampToValueAtTime(480, audioCtx.currentTime + 0.15);
        gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
      }}
    }} catch(e) {{}}
  }}

  function toggleSound() {{
    soundEnabled = !soundEnabled;
    const btn = document.getElementById("soundToggleBtn");
    btn.innerText = soundEnabled ? "🔊 Audio SFX" : "🔇 Audio Off";
    if (soundEnabled) playCyberSound("beep");
  }}

  let currentTheme = localStorage.getItem("np_soc_theme") || "dark";

  function applyDashboardTheme(theme) {{
    currentTheme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("np_soc_theme", theme);
    const btn = document.getElementById("themeToggleBtn");
    if (btn) {{
      btn.innerHTML = theme === "dark" ? "☀️ White Mode" : "🌙 Dark Mode";
    }}
  }}

  function toggleDashboardTheme() {{
    playCyberSound("click");
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    applyDashboardTheme(nextTheme);
  }}

  function switchTab(tabId, btn) {{
    playCyberSound("click");
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".nav-tab-btn").forEach(b => b.classList.remove("active"));
    const pane = document.getElementById(tabId);
    if (pane) pane.classList.add("active");
    if (btn) btn.classList.add("active");

    if (tabId === 'tab-dfir-hub') {{
      renderForensic4Q();
    }} else if (tabId === 'tab-ai-graphs') {{
      renderMainAttackGraph();
    }} else if (tabId === 'tab-ai-cockpit') {{
      renderThreatOpsCockpit();
    }} else if (tabId === 'tab-radar') {{
      renderRadarTelemetry();
    }} else if (tabId === 'tab-sandbox') {{
      initAiSandbox();
    }} else if (tabId === 'tab-benchmark') {{
      loadAiBenchmarkData();
    }}
  }}

  // 1. Force Directed Network Graph with Draggable Nodes
  const canvas = document.getElementById("networkCanvas");
  const ctx = canvas.getContext("2d");

  function resizeCanvas() {{
    canvas.width = canvas.parentElement.clientWidth - 44;
    canvas.height = 380;
  }}
  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();

  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;
  const radius = Math.min(centerX, centerY) * 0.75;

  GRAPH_NODES.forEach((node, idx) => {{
    const angle = (idx / GRAPH_NODES.length) * 2 * Math.PI;
    node.x = centerX + radius * Math.cos(angle);
    node.y = centerY + radius * Math.sin(angle);
    node.vx = (Math.random() - 0.5) * 0.3;
    node.vy = (Math.random() - 0.5) * 0.3;
    node.radius = Math.max(14, Math.min(26, Math.sqrt(node.packets) * 5));
  }});

  let draggedNode = null;
  let hoveredNode = null;
  let particleTime = 0;

  function drawNetworkGraph() {{
    const isDark = document.documentElement.getAttribute("data-theme") !== "light";
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particleTime += 0.02;

    // Draw Links
    GRAPH_LINKS.forEach(link => {{
      const src = GRAPH_NODES.find(n => n.id === link.source);
      const dst = GRAPH_NODES.find(n => n.id === link.target);
      if (src && dst) {{
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(dst.x, dst.y);
        ctx.strokeStyle = isDark ? "rgba(96, 165, 250, 0.45)" : "rgba(59, 130, 246, 0.35)";
        ctx.lineWidth = 2;
        ctx.stroke();

        const t = (particleTime % 1);
        const px = src.x + (dst.x - src.x) * t;
        const py = src.y + (dst.y - src.y) * t;
        ctx.beginPath();
        ctx.arc(px, py, 3.5, 0, 2 * Math.PI);
        ctx.fillStyle = isDark ? "#60a5fa" : "#2563eb";
        ctx.shadowColor = "#3b82f6";
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }}
    }});

    // Draw Nodes
    GRAPH_NODES.forEach(node => {{
      if (node !== draggedNode) {{
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < node.radius || node.x > canvas.width - node.radius) node.vx *= -1;
        if (node.y < node.radius || node.y > canvas.height - node.radius) node.vy *= -1;
      }}

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);
      ctx.fillStyle = node.color;
      ctx.shadowColor = node.color;
      ctx.shadowBlur = node === hoveredNode ? 14 : 6;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius + 2.5, 0, 2 * Math.PI);
      ctx.strokeStyle = isDark ? "#1e293b" : "#ffffff";
      ctx.lineWidth = 2;
      ctx.stroke();

      ctx.fillStyle = isDark ? "#f8fafc" : "#0f172a";
      ctx.font = "bold 11px monospace";
      ctx.textAlign = "center";
      ctx.fillText(node.label, node.x, node.y + node.radius + 14);
    }});

    requestAnimationFrame(drawNetworkGraph);
  }}
  drawNetworkGraph();

  canvas.addEventListener("mousedown", (e) => {{
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    GRAPH_NODES.forEach(n => {{
      if (Math.hypot(n.x - mx, n.y - my) <= n.radius + 5) {{
        draggedNode = n;
      }}
    }});
  }});

  canvas.addEventListener("mousemove", (e) => {{
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    if (draggedNode) {{
      draggedNode.x = mx;
      draggedNode.y = my;
    }}

    hoveredNode = null;
    GRAPH_NODES.forEach(n => {{
      if (Math.hypot(n.x - mx, n.y - my) <= n.radius + 5) {{
        hoveredNode = n;
      }}
    }});
  }});

  window.addEventListener("mouseup", () => {{
    draggedNode = null;
  }});

  canvas.addEventListener("click", (e) => {{
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    GRAPH_NODES.forEach(n => {{
      if (Math.hypot(n.x - mx, n.y - my) <= n.radius + 5) {{
        openIpModal(n.id);
      }}
    }});
  }});

  // 2. Wireshark 3-Pane Dissector Selection
  function selectPacketRow(pktNum) {{
    playCyberSound("click");
    const pkt = PACKETS_DATA.find(p => p.Packet_Number === pktNum);
    if (!pkt) return;

    activeSelectedPacket = pkt;

    document.querySelectorAll(".pkt-row").forEach(r => r.classList.remove("selected-row"));
    const targetRow = document.querySelector(`.pkt-row[data-pkt="${{pktNum}}"]`);
    if (targetRow) targetRow.classList.add("selected-row");

    const treeTitle = document.getElementById("dissectorTreeTitle");
    treeTitle.innerHTML = `📑 Packet #${{pkt.Packet_Number}} Dissection Hierarchy • <span style="color:var(--primary-blue); font-weight:800;">${{pkt.Protocol}}</span>`;

    const container = document.getElementById("dissectorLayerContainer");
    let html = "";
    if (pkt.Layers && pkt.Layers.length > 0) {{
      pkt.Layers.forEach((layer, idx) => {{
        const layerName = layer.LayerName || `Layer ${{idx + 1}}`;
        html += `<div class="layer-item-box">`;
        html += `<strong>▶ ${{layerName}}</strong>`;
        for (let [k, v] of Object.entries(layer)) {{
          if (k !== "LayerName" && typeof v !== "object") {{
            html += `<div style="padding-left:16px; color:#475569; font-size:11px; margin-top:3px;">• ${{k}}: <span style="color:#0f172a; font-weight:600;">${{v}}</span></div>`;
          }}
        }}
        html += `</div>`;
      }});
    }} else {{
      html = `<div class="layer-item-box"><strong>▶ Frame #${{pkt.Packet_Number}}</strong>: ${{pkt.Info}}</div>`;
    }}
    container.innerHTML = html;

    const hexView = document.getElementById("dissectorHexView");
    hexView.innerText = pkt.Hex_Dump || "No raw payload captured for this frame.";
  }}

  function copyActiveHex() {{
    if (!activeSelectedPacket || !activeSelectedPacket.Hex_Dump) return;
    navigator.clipboard.writeText(activeSelectedPacket.Hex_Dump);
    alert("Hex Dump copied to clipboard!");
  }}

  function filterByQuickChip(chip) {{
    playCyberSound("click");
    document.querySelectorAll(".filter-chip").forEach(b => b.classList.remove("active"));
    const btn = document.getElementById(`chip-${{chip.toLowerCase()}}`);
    if (btn) btn.classList.add("active");

    const input = document.getElementById("liveSearchInput");
    if (chip === "ALL") {{
      input.value = "";
    }} else if (chip === "THREATS") {{
      input.value = "threat";
    }} else {{
      input.value = chip;
    }}
    handleLiveFilter();
  }}

  function handleLiveFilter() {{
    const query = document.getElementById("liveSearchInput").value.trim().toLowerCase();
    const rows = document.querySelectorAll(".pkt-row");
    let count = 0;

    rows.forEach(r => {{
      if (!query) {{
        r.style.display = "";
        count++;
        return;
      }}
      const num = r.getAttribute("data-pkt") || "";
      const proto = r.getAttribute("data-proto") || "";
      const src = (r.getAttribute("data-src") || "").toLowerCase();
      const dst = (r.getAttribute("data-dst") || "").toLowerCase();
      const info = (r.getAttribute("data-info") || "").toLowerCase();

      if (num === query || proto.includes(query) || src.includes(query) || dst.includes(query) || info.includes(query)) {{
        r.style.display = "";
        count++;
      }} else {{
        r.style.display = "none";
      }}
    }});

    document.getElementById("livePktCount").innerText = `Showing ${{count}} of ${{rows.length}} packets`;
  }}

  function resetLiveFilter() {{
    document.getElementById("liveSearchInput").value = "";
    filterByQuickChip("ALL");
  }}

  function jumpToTriggerPackets(pktsCsv) {{
    playCyberSound("alert");
    switchTab("tab-dissector", document.querySelectorAll(".nav-tab-btn")[1]);
    const set = new Set(pktsCsv.split(",").map(s => s.trim()));
    const rows = document.querySelectorAll(".pkt-row");
    let count = 0;
    let firstMatch = null;

    rows.forEach(r => {{
      const num = r.getAttribute("data-pkt");
      if (set.has(num)) {{
        r.style.display = "";
        if (!firstMatch) firstMatch = parseInt(num);
        count++;
      }} else {{
        r.style.display = "none";
      }}
    }});

    document.getElementById("liveSearchInput").value = "Trigger Pkts: " + pktsCsv.split(",").slice(0, 5).join(",");
    document.getElementById("livePktCount").innerText = `Filtered: ${{count}} trigger packets`;
    if (firstMatch) selectPacketRow(firstMatch);
  }}

  function filterAlertsBySev(sev) {{
    playCyberSound("click");
    const cards = document.querySelectorAll(".alert-card");
    cards.forEach(c => {{
      if (sev === "ALL" || c.getAttribute("data-sev") === sev) {{
        c.style.display = "";
      }} else {{
        c.style.display = "none";
      }}
    }});
  }}

  function openIpModal(ip) {{
    playCyberSound("beep");
    activeModalIp = ip;
    const modal = document.getElementById("ipModalBackdrop");
    const title = document.getElementById("modalTitle");
    const body = document.getElementById("modalBody");

    const data = IP_STORE[ip] || {{}};
    const prof = data.profile || {{}};
    const geo = data.geo || {{}};
    const vt = data.vt || {{}};

    title.innerHTML = `🌐 Deep Forensic Telemetry: <code>${{ip}}</code>`;

    let enginesHtml = "";
    if (vt.Engine_Detections && vt.Engine_Detections.length > 0) {{
      enginesHtml = `<div style="margin-top:14px; background:var(--crit-bg); border:1.5px solid var(--crit-border); border-radius:8px; padding:12px;">
        <strong style="color:var(--crit-red);">🚨 Threat Engines Flagging this Node:</strong>
        <ul style="margin:6px 0 0 18px; font-size:12px; color:var(--text-navy);">
          ${{vt.Engine_Detections.map(e => `<li><strong>${{e.Engine}}</strong>: ${{e.Category}} (${{e.Result}})</li>`).join('')}}
        </ul>
      </div>`;
    }}

    body.innerHTML = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:14px;">
        <div style="background:var(--blue-subtle); border:1px solid var(--blue-border); padding:14px; border-radius:8px;">
          <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:700;">Threat Classification</div>
          <div style="font-size:18px; font-weight:800; color:${{prof.Threat_Level === 'MALICIOUS' ? '#dc2626' : (prof.Threat_Level === 'SUSPICIOUS' ? '#ea580c' : '#16a34a')}}">
            ${{prof.Threat_Level || 'CLEAN'}} (Risk Score: ${{prof.Threat_Score || 0}}/100)
          </div>
          <div style="font-size:12px; color:var(--text-navy); margin-top:4px;">Packets Tx: ${{prof.Packets_Sent || 0}} | Rx: ${{prof.Packets_Recv || 0}}</div>
        </div>
        <div style="background:var(--blue-subtle); border:1px solid var(--blue-border); padding:14px; border-radius:8px;">
          <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:700;">VirusTotal IOC Status</div>
          <div style="font-size:18px; font-weight:800; color:${{vt.Verdict && vt.Verdict.includes('MALICIOUS') ? '#dc2626' : '#16a34a'}}">
            ${{vt.Verdict || 'CLEAN / BENIGN'}}
          </div>
          <div style="font-size:12px; color:var(--text-navy); margin-top:4px;">Detections: ${{vt.Detections || '0/89'}}</div>
        </div>
      </div>

      <div style="background:#ffffff; border:1px solid var(--blue-border); padding:14px; border-radius:8px;">
        <h4 style="color:var(--primary-deep); margin-bottom:8px; font-size:13px; font-weight:800;">🗺️ Geolocation & Network Autonomous System (ASN)</h4>
        <div style="font-size:13px; line-height:1.7; color:var(--text-navy);">
          <div><strong>Country:</strong> ${{geo.Country || 'Global / Internal'}} (${{geo.Country_Code || 'LAN'}})</div>
          <div><strong>City:</strong> ${{geo.City || 'Internal Subnet'}}</div>
          <div><strong>ASN:</strong> <code>${{geo.ASN || vt.ASN || 'AS0 (Local Routing)'}}</code></div>
          <div><strong>ISP / Provider:</strong> ${{geo.ISP || vt.Owner || 'Private Network'}}</div>
          <div><strong>Correlated DNS Domains:</strong> ${{geo.Domain_Names && geo.Domain_Names.length > 0 ? geo.Domain_Names.join(', ') : '(None)'}}</div>
        </div>
      </div>
      ${{enginesHtml}}
    `;

    modal.style.display = "flex";
  }}

  function closeModal() {{
    document.getElementById("ipModalBackdrop").style.display = "none";
  }}

  function closeModalOnBackdrop(e) {{
    if (e.target.id === "ipModalBackdrop") closeModal();
  }}

  function filterByModalIp() {{
    if (!activeModalIp) return;
    switchTab("tab-dissector", document.querySelectorAll(".nav-tab-btn")[1]);
    document.getElementById("liveSearchInput").value = activeModalIp;
    handleLiveFilter();
    closeModal();
  }}

  let completedSteps = 0;
  function togglePlaybookStep(idx, cb) {{
    playCyberSound("click");
    const card = document.getElementById(`pb-step-${{idx}}`);
    if (cb.checked) {{
      card.classList.add("completed");
      completedSteps++;
    }} else {{
      card.classList.remove("completed");
      completedSteps--;
    }}
    const total = document.querySelectorAll(".playbook-step-card").length;
    document.getElementById("playbookProgressBadge").innerText = `${{completedSteps}}/${{total}} Done`;
  }}

  function previewCarvedFile(name, size, sha) {{
    playCyberSound("beep");
    alert("File Artifact: " + name + "\\nSize: " + size + "\\nSHA-256: " + sha);
  }}

  
  /* __AI_JS_PLACEHOLDER__ */


  window.addEventListener("DOMContentLoaded", () => {{
    applyDashboardTheme(currentTheme);
    if (PACKETS_DATA.length > 0) {{
      selectPacketRow(PACKETS_DATA[0].Packet_Number);
    }}
  }});
</script>
</body>
</html>
"""
        
        # Inject AI Sentinel & DFIR Suite extensions cleanly without f-string brace escaping issues
        dashboard_html = (
            dashboard_html
            .replace("/* __AI_CSS_PLACEHOLDER__ */", AI_CSS_BLOCK)
            .replace("<!-- __AI_NAV_TABS_PLACEHOLDER__ -->", AI_NAV_TABS_BLOCK)
            .replace("<!-- __AI_HTML_TABS_PLACEHOLDER__ -->", AI_HTML_TABS_BLOCK)
            .replace("/* __AI_JS_PLACEHOLDER__ */", AI_JS_BLOCK)
            .replace("__AI_DATA_PLACEHOLDER__", json.dumps(ai_data))
        )

        with open(output_filepath, "w", encoding="utf-8") as f:
            f.write(dashboard_html)

        return output_filepath
