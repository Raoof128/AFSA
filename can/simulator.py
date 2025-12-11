"""Synthetic CAN bus simulator for testing IDS logic."""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CANFrame:
    """Representation of a synthetic CAN frame."""

    message_id: int
    dlc: int
    data: List[int]
    timestamp: float
    label: str = "normal"

    def __post_init__(self) -> None:
        """Validate payload attributes to keep frames well-formed for analysis."""

        if not 0 <= self.message_id <= 0x1FFFFFFF:
            raise ValueError("message_id must be within 29-bit CAN identifier space")
        if self.dlc < 0:
            raise ValueError("dlc cannot be negative")
        if len(self.data) > 8:
            raise ValueError("data length cannot exceed 8 bytes for classical CAN frames")
        for byte in self.data:
            if not 0 <= byte <= 0xFF:
                raise ValueError("CAN data bytes must be between 0 and 255")
        if self.dlc != len(self.data):
            logger.debug("DLC (%s) does not match data length (%s)", self.dlc, len(self.data))

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "dlc": self.dlc,
            "data": self.data,
            "timestamp": self.timestamp,
            "label": self.label,
        }


NORMAL_IDS = {
    "rpm": 0x0CFF1234,
    "brake": 0x0CFF1200,
    "steering": 0x0CFF1210,
    "doors": 0x0CFF1220,
    "speed": 0x0CFF1234,
}


def _now(
    base: Optional[float] = None, step: float = 0.05, rng: Optional[random.Random] = None
) -> float:
    """Return a pseudo-random timestamp near a base time."""

    base = time.time() if base is None else base
    rng = rng or random
    return base + rng.random() * step


def generate_normal_frame(
    signal: str, base_time: Optional[float] = None, rng: Optional[random.Random] = None
) -> CANFrame:
    """Generate normal CAN frame for a given signal."""

    rng = rng or random
    message_id = NORMAL_IDS.get(signal, 0x100)
    dlc = 8
    timestamp = _now(base_time, rng=rng)
    if signal == "rpm":
        rpm = rng.randint(700, 3000)
        data = [rpm >> 8 & 0xFF, rpm & 0xFF] + [0] * 6
    elif signal == "brake":
        pressure = rng.randint(0, 255)
        data = [pressure] + [0] * 7
    elif signal == "steering":
        angle = rng.randint(-500, 500)
        data = [(angle >> 8) & 0xFF, angle & 0xFF] + [0] * 6
    elif signal == "doors":
        states = [rng.choice([0, 1]) for _ in range(4)]
        data = states + [0] * 4
    elif signal == "speed":
        speed = rng.randint(0, 120)
        data = [speed] + [0] * 7
    else:
        data = [0] * 8
    return CANFrame(message_id, dlc, data, timestamp, label="normal")


def simulate_normal_traffic(count: int = 200, seed: Optional[int] = None) -> List[CANFrame]:
    """Produce baseline CAN bus traffic across the common vehicle signals."""

    if count <= 0:
        return []
    rng = random.Random(seed)
    frames: List[CANFrame] = []
    base_time = time.time()
    signals = list(NORMAL_IDS.keys())
    for _ in range(count):
        signal = rng.choice(signals)
        frames.append(generate_normal_frame(signal, base_time, rng=rng))
        base_time += rng.uniform(0.01, 0.05)
    return frames


def inject_attack_frames(
    base_frames: List[CANFrame], injections: int = 10, seed: Optional[int] = None
) -> List[CANFrame]:
    """Append malicious injection frames to a baseline capture."""

    frames = list(base_frames)
    if injections <= 0:
        return frames

    rng = random.Random(seed)
    for _ in range(injections):
        timestamp = _now(base_frames[-1].timestamp if base_frames else None, 0.001, rng=rng)
        malicious_id = rng.randint(0x7FF, 0xFFFFFF)
        dlc = rng.choice([0, 9, 12])
        data = [rng.randint(0, 255) for _ in range(min(dlc, 8))]
        frames.append(CANFrame(malicious_id, dlc, data, timestamp, label="injection"))
    return frames


def simulate_replay_attack(
    base_frames: List[CANFrame], repeats: int = 5, seed: Optional[int] = None
) -> List[CANFrame]:
    """Duplicate previously seen frames to emulate replay behavior."""

    frames = list(base_frames)
    rng = random.Random(seed)
    for _ in range(repeats):
        if not base_frames:
            break
        frame = rng.choice(base_frames)
        cloned = CANFrame(
            message_id=frame.message_id,
            dlc=frame.dlc,
            data=list(frame.data),
            timestamp=_now(frame.timestamp, 0.001, rng=rng),
            label="replay",
        )
        frames.append(cloned)
    return frames


def simulate_fuzzing(attacks: int = 20, seed: Optional[int] = None) -> List[CANFrame]:
    """Generate malformed/fuzzed frames across the ID space."""

    if attacks <= 0:
        return []

    rng = random.Random(seed)
    frames: List[CANFrame] = []
    base_time = time.time()
    for _ in range(attacks):
        frames.append(
            CANFrame(
                message_id=rng.randint(0, 0x1FFFFFFF),
                dlc=rng.randint(0, 12),
                data=[rng.randint(0, 255) for _ in range(rng.randint(0, 8))],
                timestamp=_now(base_time, 0.002, rng=rng),
                label="fuzz",
            )
        )
        base_time += 0.002
    return frames


def generate_full_scenario(seed: Optional[int] = None) -> List[CANFrame]:
    """Generate combined normal, injection, replay, and fuzzing traffic."""

    rng = random.Random(seed)
    normal = simulate_normal_traffic(150, seed=rng.randint(0, 1_000_000))
    injected = inject_attack_frames(normal, 15, seed=rng.randint(0, 1_000_000))
    replayed = simulate_replay_attack(injected, 10, seed=rng.randint(0, 1_000_000))
    fuzzed = simulate_fuzzing(15, seed=rng.randint(0, 1_000_000))
    return replayed + fuzzed
