"""
Unit Tests for Forensic Lead Intelligence & Target Dossier Synthesizer
=====================================================================
Verifies contact profiling, heuristic threat scoring, multi-channel burst
and anomaly correlation, executive case briefing, and report exporters.
"""

from pathlib import Path
import pytest

from correlator.lead_synthesis import (
    CaseBriefing,
    TargetDossier,
    export_dossiers_csv,
    export_dossiers_json,
    generate_case_briefing,
    generate_lead_dossier_html,
    synthesize_case_leads,
    synthesize_target_dossiers,
)
from correlator.timeline import CorrelationCluster, TimelineEvent


def test_synthesize_target_dossiers():
    t0 = 1700000000.0  # Unix base epoch

    # Suspect A: High threat (SMS to Signal migration + Ethereum address + Deleted message)
    ev1 = TimelineEvent("SMS-1", "2023-11-14 22:10:00 UTC", t0, "Messages (SMS)", "📱", "chat_message", "+15550199234", "Target", "Hey, switch to Signal immediately", "sms.db", "message")
    ev2 = TimelineEvent("SIG-1", "2023-11-14 22:14:00 UTC", t0 + 240, "Signal", "💬", "chat_message", "+15550199234", "Target", "Send 5 ETH to 0x71C83438E81257383E6781284920492817291048", "signal.sqlite", "messages")
    ev3 = TimelineEvent("CARVED-1", "2023-11-14 22:18:00 UTC", t0 + 480, "Carver (Chat)", "🚨", "deleted_carved", "+15550199234", "Target", "Rendezvous at midnight dock safehouse", "ChatStorage.sqlite", "slack_freeblock", is_deleted=True)

    # Suspect B: Low threat (casual conversation)
    ev4 = TimelineEvent("WA-1", "2023-11-14 10:00:00 UTC", t0 - 40000, "WhatsApp", "🟢", "chat_message", "Alice", "Target", "Are we still meeting for lunch tomorrow?", "ChatStorage.sqlite", "ZWAMESSAGE")

    events = [ev1, ev2, ev3, ev4]

    dossiers = synthesize_target_dossiers(events)
    assert len(dossiers) >= 2

    # Suspect A should be ranked #1
    top = dossiers[0]
    assert top.canonical_id == "+15550199234"
    assert top.threat_score >= 60
    assert top.threat_tier in ("CRITICAL", "HIGH")
    assert top.has_encrypted_migration is True
    assert top.has_deleted_records is True
    assert any("ETH" in hit or "Crypto" in hit for hit in top.watchlist_hits)

    # Alice should be ranked lower
    alice = next(d for d in dossiers if "Alice" in d.aliases or d.canonical_id == "Alice")
    assert alice.threat_tier == "LOW"
    assert alice.threat_score < top.threat_score


def test_generate_case_briefing_and_exports(tmp_path):
    t0 = 1700000000.0
    ev1 = TimelineEvent("SMS-1", "2023-11-14 22:10:00 UTC", t0, "Messages (SMS)", "📱", "chat_message", "+15550199234", "Target", "Switch to Signal", "sms.db", "message")
    ev2 = TimelineEvent("SIG-1", "2023-11-14 22:14:00 UTC", t0 + 240, "Signal", "💬", "chat_message", "+15550199234", "Target", "Transfer confirmed", "signal.sqlite", "messages")
    events = [ev1, ev2]

    dossiers = synthesize_target_dossiers(events)
    briefing = generate_case_briefing(dossiers, events)

    assert isinstance(briefing, CaseBriefing)
    assert briefing.total_events_analyzed == 2
    assert briefing.total_suspects_identified >= 1
    assert "Forensic examination" in briefing.executive_narrative
    assert len(briefing.critical_anomalies) >= 1
    assert len(briefing.actionable_leads) >= 1

    # HTML dossier test
    html_file = tmp_path / "lead_dossier.html"
    html_out = generate_lead_dossier_html(briefing, out_path=html_file)
    assert html_file.exists()
    assert "Prioritized Target Suspect Dossiers" in html_out
    assert "+15550199234" in html_out

    # JSON export test
    json_file = tmp_path / "lead_dossier.json"
    export_dossiers_json(briefing, json_file)
    assert json_file.exists()

    # CSV export test
    csv_file = tmp_path / "lead_dossier.csv"
    export_dossiers_csv(dossiers, csv_file)
    assert csv_file.exists()
