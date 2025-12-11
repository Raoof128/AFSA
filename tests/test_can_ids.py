from pathlib import Path

from can.ids_engine import run_ids
from can.simulator import generate_full_scenario


def test_ids_produces_alerts(tmp_path: Path) -> None:
    frames = generate_full_scenario()
    results = run_ids(frames, tmp_path)
    assert "alerts" in results
    assert (tmp_path / "intrusion_alerts.json").exists()
    assert len(results["alerts"]) >= 1
