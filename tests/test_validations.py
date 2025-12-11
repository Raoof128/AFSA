"""Additional validation coverage for firmware and CAN components."""

from pathlib import Path

import pytest

from can.ids_engine import run_ids
from can.simulator import CANFrame, generate_full_scenario
from firmware.analyzer import compute_entropy, extract_strings


def test_entropy_window_validation() -> None:
    with pytest.raises(ValueError):
        compute_entropy(b"abc", window=0)


def test_extract_strings_min_len_validation() -> None:
    with pytest.raises(ValueError):
        extract_strings(b"data", min_len=0)


def test_ids_requires_frames(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_ids([], tmp_path)


def test_canframe_validation() -> None:
    with pytest.raises(ValueError):
        CANFrame(message_id=-1, dlc=1, data=[0x00], timestamp=0.0)

    frame = CANFrame(message_id=1, dlc=8, data=[0] * 8, timestamp=1.0)
    assert frame.to_dict()["dlc"] == 8


def test_deterministic_generation_with_seed() -> None:
    frames_a = generate_full_scenario(seed=1234)
    frames_b = generate_full_scenario(seed=1234)
    assert len(frames_a) == len(frames_b)
    assert [f.message_id for f in frames_a[:5]] == [f.message_id for f in frames_b[:5]]
