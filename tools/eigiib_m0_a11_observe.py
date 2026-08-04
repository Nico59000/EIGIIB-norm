#!/usr/bin/env python3
"""Deterministic M0-A11 observation-chain and lapse-state evaluator."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

OBS_STANDARD = "EIGIIB-M0-A11-OBSERVATION-1.0"
REPORT_STANDARD = "EIGIIB-M0-A11-LAPSE-REPORT-1.0"


def parse_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamp must include UTC offset")
    return dt.astimezone(timezone.utc)


def format_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_payload(observation: dict[str, Any]) -> bytes:
    payload = {k: v for k, v in observation.items() if k != "observationDigest"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def observation_digest(observation: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(observation)).hexdigest()


def evaluate(plan: dict[str, Any], ledger: dict[str, Any], at: datetime) -> dict[str, Any]:
    findings: list[str] = []
    campaign_id = plan.get("campaignId")
    if ledger.get("campaignId") != campaign_id:
        findings.append("M0A11.LEDGER.CAMPAIGN")

    schedule = plan.get("schedule", {})
    cadence = int(schedule.get("cadenceSeconds", 0))
    grace = int(schedule.get("graceSeconds", -1))
    lapse_after = int(schedule.get("lapseAfterSeconds", -1))
    if cadence <= 0 or grace < 0 or lapse_after <= grace:
        findings.append("M0A11.PLAN.LAPSE_THRESHOLDS")

    observations = ledger.get("observations")
    if not isinstance(observations, list):
        observations = []
        findings.append("M0A11.LEDGER.OBSERVATIONS")

    expected_channels = set(plan.get("expectedChannelIds", []))
    previous_digest: str | None = None
    previous_time: datetime | None = None
    first_sequence = int(schedule.get("firstSequence", 1))

    for index, obs in enumerate(observations):
        sequence = first_sequence + index
        if obs.get("standard") != OBS_STANDARD:
            findings.append(f"M0A11.OBS.STANDARD:{sequence}")
        if obs.get("campaignId") != campaign_id:
            findings.append(f"M0A11.OBS.CAMPAIGN:{sequence}")
        if obs.get("sequence") != sequence:
            findings.append(f"M0A11.OBS.SEQUENCE:{sequence}")
        if obs.get("previousObservationDigest") != previous_digest:
            findings.append(f"M0A11.OBS.PREVIOUS_DIGEST:{sequence}")
        if obs.get("observerDomainId") != plan.get("observerDomainId"):
            findings.append(f"M0A11.OBS.OBSERVER:{sequence}")
        channel_ids = {item.get("channelId") for item in obs.get("channels", []) if isinstance(item, dict)}
        if channel_ids != expected_channels:
            findings.append(f"M0A11.OBS.CHANNELS:{sequence}")
        try:
            observed_at = parse_time(obs["observedAt"])
        except Exception:
            observed_at = None
            findings.append(f"M0A11.OBS.TIME:{sequence}")
        if observed_at is not None and previous_time is not None and observed_at <= previous_time:
            findings.append(f"M0A11.OBS.TIME_ORDER:{sequence}")
        digest = observation_digest(obs)
        if obs.get("observationDigest") != digest:
            findings.append(f"M0A11.OBS.DIGEST:{sequence}")
        previous_digest = digest
        if observed_at is not None:
            previous_time = observed_at

    activation = plan.get("activationState")
    activated_at_raw = plan.get("activatedAt")
    next_due: datetime | None = None
    state = "invalid" if findings else "not-activated"

    if activation == "not-activated":
        if activated_at_raw is not None or observations:
            findings.append("M0A11.ACTIVATION.PREMATURE_EVIDENCE")
            state = "invalid"
        else:
            state = "not-activated"
    elif activation == "active":
        try:
            activated_at = parse_time(activated_at_raw)
        except Exception:
            findings.append("M0A11.ACTIVATION.TIME")
            activated_at = None
        anchor = previous_time if previous_time is not None else activated_at
        if anchor is not None:
            next_due = anchor + timedelta(seconds=cadence)
            if at <= next_due:
                state = "current" if observations else "awaiting-first-observation"
            elif at <= next_due + timedelta(seconds=grace):
                state = "grace"
            elif at <= next_due + timedelta(seconds=lapse_after):
                state = "overdue"
            else:
                state = "lapsed"
        else:
            state = "invalid"
    else:
        findings.append("M0A11.ACTIVATION.STATE")
        state = "invalid"

    if findings:
        state = "invalid"

    return {
        "standard": REPORT_STANDARD,
        "campaignId": campaign_id,
        "evaluatedAt": format_time(at),
        "state": state,
        "observationCount": len(observations),
        "latestSequence": observations[-1].get("sequence") if observations else None,
        "latestObservationDigest": observations[-1].get("observationDigest") if observations else None,
        "nextDueAt": format_time(next_due),
        "findings": sorted(set(findings)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--plan", default="conformance/m0-a11-observation-campaign.json")
    parser.add_argument("--ledger", default="conformance/m0-a11-observation-ledger.json")
    parser.add_argument("--at", required=True, help="RFC3339 evaluation time")
    parser.add_argument("--output")
    args = parser.parse_args()
    root = Path(args.root)
    plan = json.loads((root / args.plan).read_text(encoding="utf-8"))
    ledger = json.loads((root / args.ledger).read_text(encoding="utf-8"))
    report = evaluate(plan, ledger, parse_time(args.at))
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        (root / args.output).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["state"] != "invalid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
