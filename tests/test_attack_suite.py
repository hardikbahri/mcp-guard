import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "attacks"))
import evaluate  # noqa: E402


def test_attack_suite():
    caught, attacks, fp, benign, exact, total = evaluate.main()
    assert caught == attacks, "an attack got through"
    assert fp == 0, "a benign case was flagged"
    assert exact == total, "a decision differs from the expected one (see attacks/results.md)"
