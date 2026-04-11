from __future__ import annotations

import json
import subprocess
import sys


def test_cli_module_is_executable_via_python_m():
    result = subprocess.run(
        [sys.executable, "-m", "reverser.cli.main", "schema", "--kind", "js5-manifest"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "export_root" in payload["required"]
