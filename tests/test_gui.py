import tkinter as tk
import pytest
from pathlib import Path

from correlator.gui import ForensicCorrelatorGUI


def test_gui_instantiation():
    """Verify that the GUI window initializes components cleanly."""
    try:
        root = tk.Tk()
    except Exception as e:
        pytest.skip(f"Headless environment without display: {e}")

    # Prevent window from showing up during test
    root.withdraw()
    app = ForensicCorrelatorGUI(root)

    assert app.extraction_var is not None
    assert app.keychain_var is not None
    assert app.out_dir_var is not None
    assert app.results_tree is not None
    assert app.data_tree is not None

    # Test _run_doctor_action without crashing
    from unittest.mock import patch
    with patch("tkinter.messagebox.showinfo"), patch("tkinter.messagebox.showwarning"):
        app._run_doctor_action()

    # Test _on_analysis_finished without crashing
    with patch("tkinter.messagebox.showinfo"):
        app._on_analysis_finished({
            "total_databases": 1,
            "decrypted_count": 1,
            "plain_count": 0,
            "locked_count": 0,
            "results": [],
            "provenance_map": []
        }, None)

    root.destroy()
