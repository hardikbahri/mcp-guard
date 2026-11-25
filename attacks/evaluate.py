"""Runs every case in attacks/cases.jsonl through the Guard and reports detection and false-positive rates.

An attack counts as caught when the Guard did not simply allow it (alert, redact, block, terminate or hide). A benign
case counts as a false positive when the Guard did anything other than allow it. Each case runs in a fresh session so
earlier violations do not terminate later cases. Writes attacks/results.md.
    python attacks/evaluate.py
"""
import json
from collections import defaultdict
from pathlib import Path

from mcp_guard import policy
from mcp_guard.engine import Guard

ROOT = Path(__file__).resolve().parent


def run(case, guard):
    s = guard.open_session(case["user"])
    if case["stage"] == "list":
        tool = {"name": case["tool"], "description": case["payload"]["description"], "inputSchema": {}}
        return "visible" if guard.visible_tools(s, [tool]) else "hidden"
    if case["stage"] == "call":
        return guard.check_call(s, case["tool"], case["payload"]).action
    return guard.check_result(s, case["tool"], case["payload"]).action


def main():
    guard = Guard(policy.load(ROOT.parent / "policies" / "complaintops.yaml"))
    cases = [json.loads(l) for l in (ROOT / "cases.jsonl").read_text().splitlines() if l.strip()]
    rows, by_risk = [], defaultdict(lambda: [0, 0])
    caught = fp = exact = 0
    attacks = [c for c in cases if c["kind"] == "attack"]
    benign = [c for c in cases if c["kind"] == "benign"]
    for c in cases:
        got = run(c, guard)
        ok_exact = got == c["expect"]
        exact += ok_exact
        if c["kind"] == "attack":
            hit = got not in ("allow", "visible")
            caught += hit
            by_risk[c["owasp"]][0] += hit
            by_risk[c["owasp"]][1] += 1
        else:
            fp += got not in ("allow", "visible")
        rows.append((c["id"], c["kind"], c["owasp"] or "", c["tool"], c["expect"], got, "yes" if ok_exact else "NO"))

    lines = ["# Attack suite results", "",
             f"- Attacks caught: **{caught}/{len(attacks)}** ({caught / len(attacks):.0%})",
             f"- Benign cases wrongly flagged: **{fp}/{len(benign)}** ({fp / len(benign):.0%})",
             f"- Decision exactly as expected: {exact}/{len(cases)}", "",
             "| OWASP risk | Caught |", "| --- | --- |"]
    lines += [f"| {k} | {v[0]}/{v[1]} |" for k, v in sorted(by_risk.items())]
    lines += ["", "| Case | Kind | Risk | Tool | Expected | Got | Match |", "| --- | --- | --- | --- | --- | --- | --- |"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    (ROOT / "results.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines[:5]))
    return caught, len(attacks), fp, len(benign), exact, len(cases)


if __name__ == "__main__":
    main()
