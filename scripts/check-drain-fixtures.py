#!/usr/bin/env python3
"""Run the Go wire fixtures through an explicitly supplied offline consumer."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys

parser = argparse.ArgumentParser()
parser.add_argument("consumer", type=Path, help="path to snyk_linear_drain_receipts.py")
args = parser.parse_args()
sys.path.insert(0, str(args.consumer.resolve().parent))
spec = importlib.util.spec_from_file_location("drain_consumer", args.consumer)
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
root = Path(__file__).resolve().parents[1] / "internal/sync/testdata/drain-v1"
failures = 0


def receipts(fixture):
    return {key: value.encode("utf-8") for key, value in fixture["receipts"].items()}


for path in sorted(root.glob("*.json")):
    fixture = json.loads(path.read_text())
    for key in ("pending", "evidence"):
        raw = fixture["row"][key].encode("utf-8")
        assert consumer.canonical(json.loads(raw)) == raw, (path.name, key)
    for key in ("attempt", "result"):
        raw = fixture["receipts"][key].encode("utf-8")
        assert consumer.canonical(json.loads(raw)) == raw, (path.name, key)
    try:
        restored = fixture.get("restored")
        prior = consumer.admit_restored(restored["row"], receipts(restored)) if restored else None
        consumer.admit_restored(fixture["row"], receipts(fixture))
        consumer.retain_written(fixture["row"], receipts(fixture), prior)
        accepted = True
        detail = "accepted"
    except consumer.DrainRefusal as error:
        accepted = False
        detail = str(error)
    match = accepted == fixture["valid"]
    failures += not match
    print(f'{"PASS" if match else "FAIL"} {path.name}: canonical bytes match; {detail}')
raise SystemExit(1 if failures else 0)
