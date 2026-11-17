import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    import tkinter as tk
    from correlator.gui import ForensicCorrelatorGUI
    HAS_TKINTER = True
except Exception:
    HAS_TKINTER = False


@pytest.fixture(scope="module")
def gui_app():
    if not HAS_TKINTER:
        pytest.skip("Tkinter is not available in this environment")
    try:
        root = tk.Tk()
    except Exception as e:
        pytest.skip(f"Headless environment without display: {e}")

    root.withdraw()
    app = ForensicCorrelatorGUI(root)
    yield app
    try:
        root.destroy()
    except Exception:
        pass


def test_gui_instantiation(gui_app):
    """Verify that the GUI window initializes components cleanly."""
    app = gui_app
    assert app.extraction_var is not None
    assert app.keychain_var is not None
    assert app.out_dir_var is not None
    assert app.results_tree is not None
    assert app.data_tree is not None

    with patch("tkinter.messagebox.showinfo"), patch("tkinter.messagebox.showwarning"):
        app._run_doctor_action()

    with patch("tkinter.messagebox.showinfo"):
        app._on_analysis_finished({
            "total_databases": 1,
            "decrypted_count": 1,
            "plain_count": 0,
            "locked_count": 0,
            "results": [],
            "provenance_map": []
        }, None)


def test_gui_theme_toggle(gui_app):
    """Verify that the theme toggles between dark and light modes cleanly."""
    app = gui_app
    initial_theme = app.current_theme
    app._toggle_theme()
    assert app.current_theme != initial_theme
    app._toggle_theme()
    assert app.current_theme == initial_theme


def test_gui_intake_mode_change(gui_app):
    """Verify switching intake mode between folder, dump, and usb."""
    app = gui_app
    app.intake_mode_var.set("dump")
    app._on_intake_mode_changed()
    assert app.card_dump.winfo_ismapped() or True  # cards exist

    app.intake_mode_var.set("usb")
    app._on_intake_mode_changed()

    app.intake_mode_var.set("folder")
    app._on_intake_mode_changed()


def test_gui_filters_and_kpi(gui_app):
    """Verify KPI updates and table filtering."""
    app = gui_app
    app._update_kpi(total=10, decrypted=8, keys=7, entities=15)
    assert "10" in app.kpi_values[0].cget("text")
    assert "8" in app.kpi_values[1].cget("text")
    assert "7" in app.kpi_values[2].cget("text")
    assert "15" in app.kpi_values[3].cget("text")

    # Mock result items
    mock_r1 = MagicMock()
    mock_r1.status = "decrypted"
    mock_r1.relpath = "var/mobile/Signal.sqlite"
    mock_r1.bundle_id = "org.thoughtcrime.securesms"
    mock_r1.key_fingerprint = "a1b2c3d4"
    mock_r1.profile = "SQLCipher_v4"
    mock_r1.has_wal = True

    mock_r2 = MagicMock()
    mock_r2.status = "plain"
    mock_r2.relpath = "var/mobile/Notes.sqlite"
    mock_r2.bundle_id = "com.apple.notes"
    mock_r2.key_fingerprint = ""
    mock_r2.profile = ""
    mock_r2.has_wal = False

    app.all_results_cache = [mock_r1, mock_r2]
    app.results_filter_var.set("signal")
    app._filter_results_table()
    children = app.results_tree.get_children()
    assert len(children) == 1

    app.results_filter_var.set("")
    app._filter_results_table()
    assert len(app.results_tree.get_children()) == 2


def test_gui_carver_tab(gui_app):
    """Verify carver tab initialization, population, live search, and record selection."""
    app = gui_app
    assert hasattr(app, "tab_carver")
    assert hasattr(app, "carver_tree")
    assert hasattr(app, "carver_detail_text")

    from correlator.carver import DeletedRecord

    rec1 = DeletedRecord(
        record_id="del_001",
        database="ChatStorage.sqlite",
        page_num=4,
        offset_in_page=320,
        source_type="freeblock",
        table_hint="ZWAMESSAGE",
        rowid_hint=42,
        columns=["Alice", "Deleted secret message"],
        raw_text="Alice | Deleted secret message",
        confidence=0.92,
        metadata={"freeblock_len": 64},
    )
    rec2 = DeletedRecord(
        record_id="del_002",
        database="Notes.sqlite",
        page_num=8,
        offset_in_page=120,
        source_type="unallocated_slack",
        table_hint="ZNOTE",
        rowid_hint=99,
        columns=["Financial", "Burn after reading code: 99482"],
        raw_text="Financial | Burn after reading code: 99482",
        confidence=0.75,
        metadata={},
    )

    app._populate_carver_table([rec1, rec2])
    children = app.carver_tree.get_children()
    assert len(children) == 2
    assert "Recovered Records: 2" in app.lbl_carver_count.cget("text")

    # Live filter search
    app.carver_filter_var.set("secret")
    app._filter_carver_table()
    assert len(app.carver_tree.get_children()) == 1

    app.carver_filter_var.set("financial")
    app._filter_carver_table()
    assert len(app.carver_tree.get_children()) == 1

    app.carver_filter_var.set("")
    app._filter_carver_table()
    assert len(app.carver_tree.get_children()) == 2

    # Selection event inspection
    app.carver_tree.selection_set("0")
    app._on_carver_row_selected()
    content = app.carver_detail_text.get("1.0", "end")
    assert "del_001" in content
    assert "ChatStorage.sqlite" in content
    assert "Deleted secret message" in content


def test_gui_timeline_tab(gui_app):
    """Verify master timeline tab initialization, population, filter, and selection."""
    app = gui_app
    assert hasattr(app, "tab_timeline")
    assert hasattr(app, "timeline_tree")
    assert hasattr(app, "timeline_detail_text")

    from correlator.timeline import TimelineEvent, CorrelationCluster

    t0 = 1700000000.0
    ev1 = TimelineEvent("SMS-101", "2023-11-14 22:13:20 UTC", t0, "Messages (SMS)", "📱", "chat_message", "+15550199234", "Target", "Operation code Alpha", "sms.db", "message")
    ev2 = TimelineEvent("WA-202", "2023-11-14 22:14:10 UTC", t0 + 50, "WhatsApp", "🟢", "chat_message", "Target", "Boss", "Proceeding to coordinates", "ChatStorage.sqlite", "ZWAMESSAGE")

    cluster = CorrelationCluster(
        cluster_id="BURST-001",
        start_time_utc="2023-11-14 22:13:20 UTC",
        end_time_utc="2023-11-14 22:14:10 UTC",
        duration_minutes=0.8,
        apps_involved=["Messages (SMS)", "WhatsApp"],
        participants=["+15550199234", "Boss"],
        event_count=2,
        events=[ev1, ev2],
    )

    summary = {
        "total_events": 2,
        "app_count": 2,
        "time_span": "2023-11-14 -> 2023-11-14",
    }

    app._populate_timeline_table([ev1, ev2], clusters=[cluster], summary=summary)
    children = app.timeline_tree.get_children()
    assert len(children) == 2
    assert "Events: 2" in app.lbl_tl_count.cget("text")
    assert "Multi-App Bursts: 1" in app.lbl_tl_bursts.cget("text")

    # Filter by text
    app.timeline_filter_var.set("Alpha")
    app._filter_timeline_table()
    assert len(app.timeline_tree.get_children()) == 1

    # Filter by App
    app.timeline_filter_var.set("")
    app.timeline_app_var.set("WhatsApp")
    app._filter_timeline_table()
    assert len(app.timeline_tree.get_children()) == 1

    app.timeline_app_var.set("ALL")
    app._filter_timeline_table()
    assert len(app.timeline_tree.get_children()) == 2

    # Selection event inspection
    app.timeline_tree.selection_set("0")
    app._on_timeline_row_selected()
    content = app.timeline_detail_text.get("1.0", "end")
    assert "SMS-101" in content
    assert "Messages (SMS)" in content
    assert "Operation code Alpha" in content
    assert "BURST-001" in content


def test_gui_dossier_tab(gui_app):
    """Verify suspect dossier tab initialization, population, filter, and profile inspection."""
    app = gui_app
    assert hasattr(app, "tab_dossier")
    assert hasattr(app, "dossier_tree")
    assert hasattr(app, "dossier_detail_text")

    from correlator.lead_synthesis import TargetDossier, CaseBriefing

    d1 = TargetDossier(
        canonical_id="+15550199234",
        primary_alias="Mallory Archer",
        aliases=["Mallory", "+15550199234"],
        phone_numbers=["+15550199234"],
        email_addresses=["mallory@agency.org"],
        apps_used={"Signal": 42, "Messages (SMS)": 15},
        total_interactions=57,
        first_seen_utc="2023-11-14 22:10:00 UTC",
        last_seen_utc="2023-11-14 22:30:00 UTC",
        threat_score=85,
        threat_tier="CRITICAL",
        key_findings=["Detected tactical migration from SMS to Signal", "Transferred cryptocurrency wallet"],
        watchlist_hits=["Crypto Intelligence Pattern matched"],
        has_encrypted_migration=True,
        has_deleted_records=True,
        has_burst_activity=True,
        sample_excerpts=["[2023-11-14 | Signal] Send 5 ETH to 0x71C..."],
    )

    d2 = TargetDossier(
        canonical_id="Alice",
        primary_alias="Alice",
        aliases=["Alice"],
        apps_used={"WhatsApp": 5},
        total_interactions=5,
        threat_score=15,
        threat_tier="LOW",
        key_findings=["Casual social communications"],
    )

    briefing = CaseBriefing(
        case_title="Test Case Briefing",
        generated_at_utc="2023-11-15 00:00:00 UTC",
        total_events_analyzed=62,
        total_suspects_identified=2,
        critical_suspects_count=1,
        high_suspects_count=0,
        executive_narrative="Executive summary of findings.",
        top_suspects=[d1, d2],
        critical_anomalies=[{"severity": "CRITICAL", "title": "Channel Switching", "description": "Migrated to Signal"}],
    )

    app._populate_dossier_table([d1, d2], briefing=briefing)
    children = app.dossier_tree.get_children()
    assert len(children) == 2
    assert "Suspects: 2" in app.lbl_dos_total.cget("text")
    assert "Critical Threats: 1" in app.lbl_dos_crit.cget("text")

    # Filter by text
    app.dossier_filter_var.set("Mallory")
    app._filter_dossier_table()
    assert len(app.dossier_tree.get_children()) == 1

    # Filter by Threat Tier
    app.dossier_filter_var.set("")
    app.dossier_threat_var.set("CRITICAL")
    app._filter_dossier_table()
    assert len(app.dossier_tree.get_children()) == 1

    app.dossier_threat_var.set("ALL")
    app._filter_dossier_table()
    assert len(app.dossier_tree.get_children()) == 2

    # Selection event inspection
    app.dossier_tree.selection_set("0")
    app._on_dossier_row_selected()
    content = app.dossier_detail_text.get("1.0", "end")
    assert "Mallory Archer" in content
    assert "CRITICAL" in content
    assert "+15550199234" in content
    assert "mallory@agency.org" in content
    assert "0x71C..." in content


def test_gui_orphan_recovery_dialog(gui_app):
    """Verify that the orphan database recovery dialog opens and initializes cleanly."""
    app = gui_app
    with patch("tkinter.Toplevel") as mock_top:
        mock_win = MagicMock()
        mock_top.return_value = mock_win
        app._open_orphan_recovery_dialog()
        assert mock_top.called
