"""Real-game checks, excluded from the default run. On Windows with a game installed:

    set LEGACYFORGE_GAME_EXE=C:\\...\\CivilizationV_DX11.exe
    pytest -m integration

Read-only: these tests analyze but never modify the game.
"""

import os
from pathlib import Path

import pytest

from legacyforge import services

pytestmark = pytest.mark.integration
EXE = os.environ.get("LEGACYFORGE_GAME_EXE")


@pytest.mark.skipif(not EXE, reason="set LEGACYFORGE_GAME_EXE to a real game executable")
def test_analyze_real_game():
    rep = services.analyze(Path(EXE))
    e = rep["executable"]
    assert e["arch"] in ("x32", "x64")
    assert not any("unreadable" in i for i in e["header_issues"])
    assert rep["system"]["os"]["platform"] == "win32"
    print(f"\n{Path(EXE).name}: sha256={e['sha256']} laa={e['large_address_aware']} "
          f"graphics={[g['api'] for g in e['graphics']]} signature={e['signature']['status']}")
