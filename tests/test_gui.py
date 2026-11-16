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

    root.destroy()
