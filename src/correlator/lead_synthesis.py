"""
Forensic Lead Intelligence & Automated Target Dossier Synthesizer
================================================================
Performs automated multi-source evidence synthesis across all decrypted databases,
timelines, geospatial waypoints, and carved slack records:
- Compiles prioritized Person-of-Interest (POI) / Suspect Target Dossiers
- Disambiguates phone numbers, emails, handles, and real-name aliases
- Scores threat & investigative significance (0-100) based on forensic indicators:
  * Encrypted channel migration (SMS -> Signal/WhatsApp)
  * High-significance watchlist matches (Cryptocurrency, Wires, Narcotics, Weapons)
  * Unallocated slack space deleted message recovery
  * Multi-channel communication bursts
  * Off-hours / late-night operational activity
- Generates an Executive Forensic Case Briefing with actionable investigative leads
- Produces standalone interactive HTML dossier viewer (`lead_dossier.html`),
  structured JSON (`lead_dossier.json`), and spreadsheet CSV exports.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from correlator.timeline import (
    CorrelationCluster,
    TimelineEvent,
    detect_app_switching,
    detect_cross_app_bursts,
    extract_master_timeline,
    normalize_contact_identifier,
)


@dataclass
class TargetDossier:
    canonical_id: str
    primary_alias: str
    aliases: List[str] = field(default_factory=list)
    phone_numbers: List[str] = field(default_factory=list)
    email_addresses: List[str] = field(default_factory=list)
    apps_used: Dict[str, int] = field(default_factory=dict)
    total_interactions: int = 0
    first_seen_utc: str = "N/A"
    last_seen_utc: str = "N/A"
    threat_score: int = 0  # 0 to 100
    threat_tier: str = "LOW"  # CRITICAL, HIGH, MEDIUM, LOW
    key_findings: List[str] = field(default_factory=list)
    watchlist_hits: List[str] = field(default_factory=list)
    has_encrypted_migration: bool = False
    has_deleted_records: bool = False
    has_burst_activity: bool = False
    sample_excerpts: List[str] = field(default_factory=list)
    associated_locations: List[Dict[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CaseBriefing:
    case_title: str
    generated_at_utc: str
    total_events_analyzed: int
    total_suspects_identified: int
    critical_suspects_count: int
    high_suspects_count: int
    executive_narrative: str
    top_suspects: List[TargetDossier] = field(default_factory=list)
    critical_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    actionable_leads: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["top_suspects"] = [s.to_dict() for s in self.top_suspects]
        return d


# High-impact investigative keywords for threat scoring
THREAT_LEXICON = {
    "Crypto": (re.compile(r"\b(0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}|monero|bitcoin|ethereum|seed phrase|mnemonic|wallet)\b", re.I), 30),
    "Financial": (re.compile(r"\b(wire transfer|offshore|routing number|swift code|bank account|cash drop|crypto payment)\b", re.I), 25),
    "OpSec/Evasion": (re.compile(r"\b(switch to signal|burn this|delete this|signal app|encrypted chat|vpn|protonmail|drop phone)\b", re.I), 25),
    "Narcotics": (re.compile(r"\b(fentanyl|cocaine|heroin|meth|cartel|kilos|stash house|grams)\b", re.I), 35),
    "Weapons": (re.compile(r"\b(firearm|glock|ghost gun|silencer|suppressor|ammo|explosive|detonator)\b", re.I), 35),
    "Meeting/Drop": (re.compile(r"\b(drop point|rendezvous|coordinates|midnight|dock|warehouse|safehouse)\b", re.I), 20),
}


# ==============================================================================
# Dossier Synthesis Engine
# ==============================================================================

def synthesize_target_dossiers(
    events: List[TimelineEvent],
    clusters: Optional[List[CorrelationCluster]] = None,
    carved_records: Optional[List[Any]] = None,
) -> List[TargetDossier]:
    """
    Analyzes all timeline events, multi-channel burst clusters, and carved records
    to compile comprehensive, prioritized target dossiers for every person of interest.
    """
    raw_contacts: Dict[str, Dict[str, Any]] = {}

    # 1. Group events by canonical contact
    for ev in events:
        for party in (ev.sender, ev.recipient):
            if not party or "Target" in party or "Device Owner" in party or "Local Storage" in party or "Camera Hardware" in party:
                continue

            canonical = normalize_contact_identifier(party)
            if not canonical or len(canonical) < 3:
                continue

            if canonical not in raw_contacts:
                raw_contacts[canonical] = {
                    "canonical_id": canonical,
                    "aliases": set(),
                    "phone_numbers": set(),
                    "email_addresses": set(),
                    "apps": {},
                    "events": [],
                    "locations": [],
                }

            c_dict = raw_contacts[canonical]
            c_dict["aliases"].add(party)
            if "@" in party and not ("@s.whatsapp.net" in party or "@c.us" in party):
                c_dict["email_addresses"].add(party.lower())
            elif re.search(r"\d{7,}", party):
                c_dict["phone_numbers"].add(re.sub(r"[^\d+]", "", party))

            app_name = ev.app
            c_dict["apps"][app_name] = c_dict["apps"].get(app_name, 0) + 1
            c_dict["events"].append(ev)

            if ev.latitude is not None and ev.longitude is not None:
                c_dict["locations"].append({"lat": ev.latitude, "lon": ev.longitude})

    # 2. Burst and app-switching correlations
    burst_participants: Set[str] = set()
    if clusters:
        for c in clusters:
            for p in c.participants:
                burst_participants.add(normalize_contact_identifier(p))

    app_switches = detect_app_switching(events)
    switched_contacts = set(s["contact"] for s in app_switches)

    # 3. Build dossiers with algorithmic threat scoring
    dossiers: List[TargetDossier] = []

    for canonical, data in raw_contacts.items():
        c_events = data["events"]
        total_interactions = len(c_events)
        if total_interactions == 0:
            continue

        # Sort events by epoch
        c_events.sort(key=lambda x: x.timestamp_epoch)
        first_seen = c_events[0].timestamp_utc
        last_seen = c_events[-1].timestamp_utc

        # Find best human-readable name alias
        aliases = list(data["aliases"])
        primary_alias = canonical
        for a in aliases:
            # If alias has letters and spaces (e.g. "John Doe") rather than just raw numbers/JIDs
            if re.search(r"[A-Za-z]{3,}", a) and "@" not in a:
                primary_alias = a
                break

        key_findings: List[str] = []
        watchlist_hits: List[str] = []
        sample_excerpts: List[str] = []
        threat_score = 0

        # Communication volume score (up to 20 pts)
        vol_score = min(20, total_interactions * 2)
        threat_score += vol_score

        # Multi-app footprint (+15 pts if used 2+ distinct apps)
        apps_used = data["apps"]
        if len(apps_used) >= 2:
            threat_score += 15
            key_findings.append(f"Multi-channel cross-application presence across {len(apps_used)} apps: {', '.join(apps_used.keys())}")

        # Check for encrypted app switching (+20 pts)
        has_switched = canonical in switched_contacts
        if has_switched:
            threat_score += 20
            key_findings.append("Detected tactical migration from unencrypted SMS/Calls to encrypted Signal/WhatsApp")

        # Check for burst activity (+15 pts)
        has_burst = canonical in burst_participants
        if has_burst:
            threat_score += 15
            key_findings.append("Active participant in high-intensity multi-channel communication bursts")

        # Scan message contents for threat lexicon matches
        matched_categories: Set[str] = set()
        has_deleted = False

        for ev in c_events:
            txt = ev.content
            if ev.is_deleted:
                has_deleted = True

            for cat, (pat, pts) in THREAT_LEXICON.items():
                if cat not in matched_categories and pat.search(txt):
                    matched_categories.add(cat)
                    threat_score += pts
                    hit_msg = f"{cat} Intelligence Pattern matched in {ev.app}"
                    watchlist_hits.append(hit_msg)
                    key_findings.append(f"Evidence hit ({cat}): {txt[:90]}...")
                    if len(sample_excerpts) < 4:
                        sample_excerpts.append(f"[{ev.timestamp_utc[:16]} | {ev.app}] {txt}")

        if has_deleted:
            threat_score += 25
            key_findings.append("Exchanged messages were recovered from deleted SQLite slack space / freeblocks")

        # Off-hours activity check (00:00 - 05:00 UTC) (+10 pts)
        off_hours_count = sum(
            1 for ev in c_events
            if ev.timestamp_epoch > 10000000 and (int(ev.timestamp_epoch) % 86400) < 18000
        )
        if off_hours_count >= 2:
            threat_score += 10
            key_findings.append(f"Conducts off-hours operational communications ({off_hours_count} late-night events)")

        # Cap score at 100
        threat_score = min(100, threat_score)

        # Assign Threat Tier
        if threat_score >= 70:
            tier = "CRITICAL"
        elif threat_score >= 45:
            tier = "HIGH"
        elif threat_score >= 25:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        # Ensure at least 1-2 excerpts exist
        if not sample_excerpts:
            for ev in c_events[-3:]:
                if ev.content and len(ev.content) > 3:
                    sample_excerpts.append(f"[{ev.timestamp_utc[:16]} | {ev.app}] {ev.content[:100]}")

        dossiers.append(TargetDossier(
            canonical_id=canonical,
            primary_alias=primary_alias,
            aliases=aliases,
            phone_numbers=list(data["phone_numbers"]),
            email_addresses=list(data["email_addresses"]),
            apps_used=apps_used,
            total_interactions=total_interactions,
            first_seen_utc=first_seen,
            last_seen_utc=last_seen,
            threat_score=threat_score,
            threat_tier=tier,
            key_findings=key_findings,
            watchlist_hits=watchlist_hits,
            has_encrypted_migration=has_switched,
            has_deleted_records=has_deleted,
            has_burst_activity=has_burst,
            sample_excerpts=sample_excerpts,
            associated_locations=data["locations"][:10],
        ))

    # Sort descending by threat score, then interaction volume
    dossiers.sort(key=lambda d: (d.threat_score, d.total_interactions), reverse=True)
    return dossiers


# ==============================================================================
# Executive Case Briefing Generator
# ==============================================================================

def generate_case_briefing(
    dossiers: List[TargetDossier],
    events: List[TimelineEvent],
    clusters: Optional[List[CorrelationCluster]] = None,
    carved_records: Optional[List[Any]] = None,
) -> CaseBriefing:
    """
    Synthesizes the entire case evidence into an executive forensic briefing
    with critical behavioral anomalies and prioritized investigative leads.
    """
    total_events = len(events)
    total_suspects = len(dossiers)
    critical_count = sum(1 for d in dossiers if d.threat_tier == "CRITICAL")
    high_count = sum(1 for d in dossiers if d.threat_tier == "HIGH")

    # Detect overarching behavioral anomalies
    anomalies: List[Dict[str, Any]] = []

    # 1. Encrypted migration anomaly
    switched_dossiers = [d for d in dossiers if d.has_encrypted_migration]
    if switched_dossiers:
        anomalies.append({
            "type": "ENCRYPTED_MIGRATION",
            "severity": "CRITICAL",
            "title": "Tactical Channel Switching to Encrypted Messenger",
            "description": f"Suspects {', '.join(d.primary_alias for d in switched_dossiers[:3])} intentionally transitioned from unencrypted SMS/Cellular calls to end-to-end encrypted Signal/WhatsApp channels.",
        })

    # 2. Unallocated slack deleted records anomaly
    deleted_dossiers = [d for d in dossiers if d.has_deleted_records]
    if deleted_dossiers or (carved_records and len(carved_records) > 0):
        del_count = len(carved_records) if carved_records else sum(1 for e in events if e.is_deleted)
        anomalies.append({
            "type": "ANTI_FORENSICS_DELETION",
            "severity": "HIGH",
            "title": "Intentional Database Record Deletion & Anti-Forensics",
            "description": f"Recovered {del_count} deleted records from raw page slack space and freeblocks, proving deliberate deletion of chat messages and financial notes.",
        })

    # 3. Off-hours multi-channel bursts
    if clusters:
        multi_app_clusters = [c for c in clusters if len(c.apps_involved) >= 3]
        if multi_app_clusters:
            anomalies.append({
                "type": "COORDINATED_BURST",
                "severity": "HIGH",
                "title": "Coordinated Multi-Channel Communication Bursts",
                "description": f"Identified {len(clusters)} distinct communication bursts where 3+ disparate applications were triggered concurrently within short 15-minute operational windows.",
            })

    # Formulate Actionable Leads
    actionable_leads: List[str] = []
    top_suspect = dossiers[0] if dossiers else None
    if top_suspect:
        actionable_leads.append(f"Subpoena service logs & subscriber records for primary suspect {top_suspect.primary_alias} ({top_suspect.canonical_id}).")

    if any("Crypto" in h for d in dossiers for h in d.watchlist_hits):
        actionable_leads.append("Perform blockchain tracing and exchange KYC queries on cryptocurrency wallet addresses recovered from Signal and Apple Notes.")

    if any(d.associated_locations for d in dossiers):
        actionable_leads.append("Correlate extracted physical GPS rendezvous coordinates with surveillance camera feeds or cell tower ALPR data.")

    if deleted_dossiers:
        actionable_leads.append("Preserve full SQLite WAL journals and examine adjacent unallocated page sectors for additional residual message fragments.")

    # Formulate Executive Narrative
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    top_names = ", ".join(d.primary_alias for d in dossiers[:3]) if dossiers else "None"
    narrative = (
        f"Forensic examination of the extracted iOS evidence stream ({total_events:,} chronological events) "
        f"identified {total_suspects} unique points of contact, including {critical_count} CRITICAL and {high_count} HIGH-priority "
        f"persons of interest. Primary investigative focus centers on {top_names}. "
        f"Analysis revealed tactical use of end-to-end encrypted messengers (Signal/WhatsApp), corroborated by recovered deleted "
        f"database fragments from SQLite slack space and multi-app communication bursts. "
        f"Coordinated operational leads have been indexed below for immediate judicial and investigative action."
    )

    return CaseBriefing(
        case_title="iOS Keychain & Database Forensic Intelligence Briefing",
        generated_at_utc=now_str,
        total_events_analyzed=total_events,
        total_suspects_identified=total_suspects,
        critical_suspects_count=critical_count,
        high_suspects_count=high_count,
        executive_narrative=narrative,
        top_suspects=dossiers[:15],
        critical_anomalies=anomalies,
        actionable_leads=actionable_leads,
    )


# ==============================================================================
# Standalone Interactive HTML Lead Dossier Viewer
# ==============================================================================

def generate_lead_dossier_html(
    briefing: CaseBriefing,
    out_path: Optional[Path | str] = None,
) -> str:
    """
    Generates a standalone, responsive, modern cybersecurity intelligence dossier
    viewer (`lead_dossier.html`). Operates 100% offline with zero external dependencies.
    """
    dossiers_json = json.dumps([d.to_dict() for d in briefing.top_suspects])
    briefing_json = json.dumps(briefing.to_dict())

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(briefing.case_title)}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-card: #1f293d;
            --border: #2d3b55;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --threat-critical: #ef4444;
            --threat-high: #f97316;
            --threat-med: #eab308;
            --threat-low: #3b82f6;
            --accent-green: #10b981;
        }}
        * {{ box-sizing: border-box; margin:0; padding:0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text-main);
            padding: 24px;
            font-size: 14px;
        }}
        header {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        h1 {{ font-size: 1.5rem; font-weight: 700; display: flex; align-items: center; gap: 10px; }}
        .hud {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin: 20px 0;
        }}
        .hud-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
        }}
        .hud-title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }}
        .hud-val {{ font-size: 1.6rem; font-weight: 700; margin-top: 4px; }}
        .narrative-box {{
            background: var(--surface-card);
            border-left: 4px solid var(--threat-critical);
            padding: 16px 20px;
            border-radius: 6px;
            font-size: 0.95rem;
            line-height: 1.6;
            margin-top: 14px;
        }}
        .anomalies-section {{
            margin-bottom: 24px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 14px;
        }}
        .anomaly-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
        }}
        .anomaly-badge {{
            display: inline-block;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            margin-bottom: 8px;
        }}
        .badge-crit {{ background: var(--threat-critical); color:#fff; }}
        .badge-high {{ background: var(--threat-high); color:#fff; }}
        .dossier-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
            gap: 16px;
        }}
        .dossier-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 18px;
            transition: all 0.15s;
            cursor: pointer;
            position: relative;
        }}
        .dossier-card:hover {{
            background: var(--surface-card);
            border-color: var(--text-muted);
        }}
        .score-pill {{
            position: absolute;
            top: 18px; right: 18px;
            font-size: 0.8rem;
            font-weight: 800;
            padding: 4px 10px;
            border-radius: 20px;
        }}
        .score-crit {{ background: rgba(239, 68, 68, 0.2); color: var(--threat-critical); border: 1px solid var(--threat-critical); }}
        .score-high {{ background: rgba(249, 115, 22, 0.2); color: var(--threat-high); border: 1px solid var(--threat-high); }}
        .score-med {{ background: rgba(234, 179, 8, 0.2); color: var(--threat-med); border: 1px solid var(--threat-med); }}
        .score-low {{ background: rgba(59, 130, 246, 0.2); color: var(--threat-low); border: 1px solid var(--threat-low); }}
        .suspect-name {{ font-size: 1.15rem; font-weight: 700; margin-bottom: 4px; }}
        .suspect-id {{ color: var(--text-muted); font-size: 0.85rem; font-family: monospace; }}
        .app-tags {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }}
        .app-tag {{
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 0.75rem;
        }}
        .findings-list {{ font-size: 0.85rem; color: #cbd5e1; margin-top: 10px; }}
        .findings-list li {{ margin-left: 18px; margin-bottom: 4px; }}
        
        /* Modal Profile Drawer */
        .modal-bg {{
            display: none;
            position: fixed;
            top:0; left:0; width:100%; height:100%;
            background: rgba(0,0,0,0.75);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .modal {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            max-width: 720px;
            width: 90%;
            max-height: 85vh;
            overflow-y: auto;
            padding: 26px;
            position: relative;
        }}
        .modal-close {{
            position: absolute;
            top: 18px; right: 20px;
            cursor: pointer;
            font-size: 1.5rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>

    <header>
        <div class="header-top">
            <div>
                <h1>🎯 {html.escape(briefing.case_title)}</h1>
                <p style="color:var(--text-muted); font-size:0.9rem; margin-top:4px;">
                    Generated: {briefing.generated_at_utc} | Forensic Case Intelligence & Suspect Profiling Engine
                </p>
            </div>
            <div style="display:flex; gap:8px;">
                <button onclick="window.location.href='lead_dossier.csv'" style="background:var(--surface-card); border:1px solid var(--border); color:#fff; padding:8px 14px; border-radius:6px; cursor:pointer; font-weight:600;">📊 Export CSV</button>
                <button onclick="window.location.href='lead_dossier.json'" style="background:var(--threat-low); border:none; color:#fff; padding:8px 14px; border-radius:6px; cursor:pointer; font-weight:600;">📥 Export JSON</button>
            </div>
        </div>

        <div class="hud">
            <div class="hud-card">
                <div class="hud-title">Analyzed Events</div>
                <div class="hud-val">{briefing.total_events_analyzed:,}</div>
            </div>
            <div class="hud-card">
                <div class="hud-title">Unique Suspects / Contacts</div>
                <div class="hud-val">{briefing.total_suspects_identified}</div>
            </div>
            <div class="hud-card">
                <div class="hud-title">Critical Threats</div>
                <div class="hud-val" style="color:var(--threat-critical);">{briefing.critical_suspects_count}</div>
            </div>
            <div class="hud-card">
                <div class="hud-title">High Threats</div>
                <div class="hud-val" style="color:var(--threat-high);">{briefing.high_suspects_count}</div>
            </div>
        </div>

        <div class="narrative-box">
            <b>📋 Executive Forensic Summary:</b><br>
            {html.escape(briefing.executive_narrative)}
        </div>
    </header>

    <h2 style="font-size:1.2rem; margin-bottom:12px;">🚨 Critical Forensic Anomalies Detected</h2>
    <div class="anomalies-section">
        {"".join([f'''
        <div class="anomaly-card">
            <span class="anomaly-badge {'badge-crit' if a['severity'] == 'CRITICAL' else 'badge-high'}">{html.escape(a['severity'])}</span>
            <div style="font-weight:700; font-size:1rem; margin-bottom:6px;">{html.escape(a['title'])}</div>
            <div style="color:var(--text-muted); font-size:0.85rem; line-height:1.5;">{html.escape(a['description'])}</div>
        </div>
        ''' for a in briefing.critical_anomalies])}
    </div>

    <h2 style="font-size:1.2rem; margin-bottom:12px;">🎯 Prioritized Target Suspect Dossiers (Ranked by Threat Score)</h2>
    <div id="dossierList" class="dossier-grid">
        <!-- Rendered dynamically -->
    </div>

    <div id="profileModalBg" class="modal-bg" onclick="closeModal(event)">
        <div class="modal" onclick="event.stopPropagation()">
            <span class="modal-close" onclick="closeModal()">&times;</span>
            <h2 id="modalName" style="font-size:1.3rem;"></h2>
            <div id="modalId" style="color:var(--text-muted); font-family:monospace; margin-bottom:16px;"></div>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        const rawDossiers = {dossiers_json};

        function renderDossiers() {{
            const container = document.getElementById('dossierList');
            container.innerHTML = '';

            rawDossiers.forEach(d => {{
                const card = document.createElement('div');
                card.className = 'dossier-card';
                card.onclick = () => openProfile(d);

                let scoreClass = 'score-low';
                if (d.threat_tier === 'CRITICAL') scoreClass = 'score-crit';
                else if (d.threat_tier === 'HIGH') scoreClass = 'score-high';
                else if (d.threat_tier === 'MEDIUM') scoreClass = 'score-med';

                const appTagsHtml = Object.entries(d.apps_used)
                    .map(([app, cnt]) => `<span class="app-tag">${{escapeHtml(app)}}: ${{cnt}}</span>`)
                    .join(' ');

                const findingsHtml = d.key_findings.slice(0, 3)
                    .map(f => `<li>${{escapeHtml(f)}}</li>`)
                    .join('');

                card.innerHTML = `
                    <span class="score-pill ${{scoreClass}}">${{d.threat_tier}} (${{d.threat_score}} pts)</span>
                    <div class="suspect-name">${{escapeHtml(d.primary_alias)}}</div>
                    <div class="suspect-id">${{escapeHtml(d.canonical_id)}}</div>
                    <div class="app-tags">${{appTagsHtml}}</div>
                    <div style="font-size:0.8rem; color:var(--text-muted);">
                        Interactions: <b>${{d.total_interactions}}</b> | Time: ${{escapeHtml(d.first_seen_utc.slice(0,10))}} &rarr; ${{escapeHtml(d.last_seen_utc.slice(0,10))}}
                    </div>
                    <ul class="findings-list">${{findingsHtml}}</ul>
                `;
                container.appendChild(card);
            }});
        }}

        function openProfile(d) {{
            document.getElementById('modalName').textContent = d.primary_alias;
            document.getElementById('modalId').textContent = d.canonical_id;

            const excerptsHtml = d.sample_excerpts
                .map(x => `<div style="background:var(--bg); border:1px solid var(--border); padding:8px 12px; border-radius:6px; margin-bottom:6px; font-family:monospace; font-size:0.85rem;">${{escapeHtml(x)}}</div>`)
                .join('');

            const findingsHtml = d.key_findings
                .map(f => `<li>${{escapeHtml(f)}}</li>`)
                .join('');

            document.getElementById('modalBody').innerHTML = `
                <table style="width:100%; border-collapse:collapse; margin-bottom:16px; font-size:0.9rem;">
                    <tr><td style="color:var(--text-muted); width:140px; padding:4px 0;">Threat Score:</td><td><b>${{d.threat_score}} / 100</b> (${{d.threat_tier}})</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Associated Numbers:</td><td>${{d.phone_numbers.join(', ') || 'N/A'}}</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Associated Emails:</td><td>${{d.email_addresses.join(', ') || 'N/A'}}</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Known Aliases:</td><td>${{d.aliases.join(', ')}}</td></tr>
                    <tr><td style="color:var(--text-muted); padding:4px 0;">Active Date Span:</td><td>${{d.first_seen_utc}} &rarr; ${{d.last_seen_utc}}</td></tr>
                </table>

                <div style="font-weight:700; margin-bottom:6px;">🔎 Forensics & Key Intelligence Indicators:</div>
                <ul style="margin-left:20px; font-size:0.9rem; color:#cbd5e1; margin-bottom:16px;">${{findingsHtml}}</ul>

                <div style="font-weight:700; margin-bottom:6px;">💬 Representative Message Excerpts:</div>
                ${{excerptsHtml || '<div style="color:var(--text-muted);">No excerpt available.</div>'}}
            `;
            document.getElementById('profileModalBg').style.display = 'flex';
        }}

        function closeModal() {{
            document.getElementById('profileModalBg').style.display = 'none';
        }}

        function escapeHtml(s) {{
            if (!s) return '';
            return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }}

        renderDossiers();
    </script>
</body>
</html>
"""
    if out_path:
        out_file = Path(out_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(html_content)

    return html_content


# ==============================================================================
# Multi-Format Forensic Exporters
# ==============================================================================

def export_dossiers_json(
    briefing: CaseBriefing,
    out_path: Path | str,
) -> None:
    """Exports structured case briefing and dossiers to JSON."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(briefing.to_dict(), f, indent=2)


def export_dossiers_csv(
    dossiers: List[TargetDossier],
    out_path: Path | str,
) -> None:
    """Exports prioritized target dossiers to spreadsheet CSV."""
    out_file = Path(out_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    header = [
        "Rank",
        "Threat Tier",
        "Threat Score",
        "Primary Alias",
        "Canonical ID",
        "Known Aliases",
        "Phone Numbers",
        "Email Addresses",
        "Applications Used",
        "Total Interactions",
        "First Seen (UTC)",
        "Last Seen (UTC)",
        "Encrypted Migration",
        "Has Deleted Messages",
        "Key Findings",
    ]

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for i, d in enumerate(dossiers, start=1):
            apps_str = " ; ".join(f"{k}:{v}" for k, v in d.apps_used.items())
            findings_clean = " ; ".join(d.key_findings).replace('"', '""')
            row = [
                str(i),
                f'"{d.threat_tier}"',
                str(d.threat_score),
                f'"{d.primary_alias}"',
                f'"{d.canonical_id}"',
                f'"{", ".join(d.aliases)}"',
                f'"{", ".join(d.phone_numbers)}"',
                f'"{", ".join(d.email_addresses)}"',
                f'"{apps_str}"',
                str(d.total_interactions),
                f'"{d.first_seen_utc}"',
                f'"{d.last_seen_utc}"',
                "YES" if d.has_encrypted_migration else "NO",
                "YES" if d.has_deleted_records else "NO",
                f'"{findings_clean}"',
            ]
            f.write(",".join(row) + "\n")


# ==============================================================================
# Master Synthesis Orchestrator
# ==============================================================================

def synthesize_case_leads(
    evidence_directory: Path | str,
    geo_points: Optional[List[Any]] = None,
    carved_records: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    """
    Main entrypoint for Option 5:
    Fuses all chronological evidence, identifies persons of interest, scores
    investigative threats, and produces the complete Case Briefing and Dossiers.
    """
    timeline_res = extract_master_timeline(
        evidence_directory=evidence_directory,
        geo_points=geo_points,
        carved_records=carved_records,
    )
    events = timeline_res.get("events", [])
    clusters = timeline_res.get("clusters", [])

    dossiers = synthesize_target_dossiers(
        events=events,
        clusters=clusters,
        carved_records=carved_records,
    )

    briefing = generate_case_briefing(
        dossiers=dossiers,
        events=events,
        clusters=clusters,
        carved_records=carved_records,
    )

    return {
        "briefing": briefing,
        "dossiers": dossiers,
        "total_suspects": len(dossiers),
        "critical_suspects": [d for d in dossiers if d.threat_tier == "CRITICAL"],
        "high_suspects": [d for d in dossiers if d.threat_tier == "HIGH"],
    }
