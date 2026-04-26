from __future__ import annotations

import runpy
import sys
import types

import pytest


def test_gui_module_runs_main_when_executed_as_a_script(monkeypatch: pytest.MonkeyPatch):
    fake_main_window = types.ModuleType("reverser.gui.main_window")
    fake_main_window.launch = lambda: 7

    monkeypatch.setitem(sys.modules, "reverser.gui.main_window", fake_main_window)

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("reverser.app", run_name="__main__")

    assert excinfo.value.code == 7
