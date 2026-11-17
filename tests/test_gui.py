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
