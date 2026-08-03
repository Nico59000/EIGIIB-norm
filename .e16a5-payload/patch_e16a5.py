from __future__ import annotations
import ast
import hashlib
import json
import re
from pathlib import Path

SOURCE_A1 = "7fd50a2009c6a437c7fe0b680407cf337b55cf4f"
SOURCE_A4 = "b28fe74f829141232770155724620617bfb1241c"
PROFILE_KEYS = {
    "e16_a2_contract": "extensions/E16-A2-REPLICA-PLACEMENT-CUSTODY-ACCEPTANCE-FAILURE-DOMAIN-EVIDENCE.md",
    "replica_placement": "conformance/replica-placement.json",
    "e16_a2_transition": "conformance/e16-a2-adoption-transition.json",
    "e16_a2_authority_manifest": "conformance/e16-a2-authority-manifest.json",
    "e16_a2_authority_freeze": "conformance/e16-a2-authority-freeze.json",
    "e16_a2_human_mastery": "docs/E16-A2-HUMAN-MASTERY-GUIDE.md",
    "e16_a3_contract": "extensions/E16-A3-RETENTION-WINDOWS-BOUNDED-PRESERVATION-INDEPENDENT-READBACK-RESTORE-VERIFICATION.md",
    "retention_readback_restore": "conformance/retention-readback-restore.json",
    "e16_a3_transition": "conformance/e16-a3-adoption-transition.json",
    "e16_a3_authority_manifest": "conformance/e16-a3-authority-manifest.json",
    "e16_a3_authority_freeze": "conformance/e16-a3-authority-freeze.json",
    "e16_a3_human_mastery": "docs/E16-A3-HUMAN-MASTERY-GUIDE.md",
    "e16_a4_contract": "extensions/E16-A4-CUSTODIAN-SUCCESSION-REPLICA-MIGRATION-LOSS-QUARANTINE-ANTI-ROLLBACK-RECOVERY.md",
    "custodian_succession_recovery": "conformance/custodian-succession-recovery.json",
    "e16_a4_transition": "conformance/e16-a4-adoption-transition.json",
    "e16_a4_authority_manifest": "conformance/e16-a4-authority-manifest.json",
    "e16_a4_authority_freeze": "conformance/e16-a4-authority-freeze.json",
    "e16_a4_human_mastery": "docs/E16-A4-HUMAN-MASTERY-GUIDE.md",
    "e16_a5_contract": "extensions/E16-A5-INDEPENDENT-PRESERVATION-VERIFIER-MATRIX-DIFFERENTIAL-RESTORE-REPLAY-FINAL-FREEZE.md",
    "e16_final_closure": "conformance/e16-final-closure.json",
    "e16_a5_verifier_matrix": "conformance/e16-a5-verifier-matrix.json",
    "e16_a5_transition": "conformance/e16-a5-adoption-transition.json",
    "e16_a5_authority_manifest": "conformance/e16-a5-authority-manifest.json",
    "e16_a5_authority_freeze": "conformance/e16-a5-authority-freeze.json",
    "e16_a5_human_mastery": "docs/E16-A5-HUMAN-MASTERY-GUIDE.md",
    "e16_final_closure_report": "docs/E16-FINAL-CLOSURE-REPORT.md",
}
A5_PATHS = [
    ".github/workflows/e16-a5-final-closure.yml",
    "conformance/E16-A5-MANUAL-REVIEW.md",
    "conformance/e16-a5-adoption-transition.json",
    "conformance/e16-a5-authority-manifest.json",
    "conformance/e16-a5-verifier-matrix.json",
    "conformance/e16-final-closure.json",
    "docs/E16-A5-HUMAN-MASTERY-GUIDE.md",
    "docs/E16-FINAL-CLOSURE-REPORT.md",
    "extensions/E16-A5-INDEPENDENT-PRESERVATION-VERIFIER-MATRIX-DIFFERENTIAL-RESTORE-REPLAY-FINAL-FREEZE.md",
    "schemas/eigiib-e16-a5-adoption-transition.schema.json",
    "schemas/eigiib-e16-a5-authority-manifest.schema.json",
    "schemas/eigiib-e16-a5-authority-freeze.schema.json",
    "schemas/eigiib-e16-a5-verifier-matrix.schema.json",
    "schemas/eigiib-e16-a5-final-closure.schema.json",
    "tests/fixtures/e16-a5/expected-matrix-report.json",
    "tests/fixtures/e16-a5/expected-closure-report.json",
    "tests/test_eigiib_e16_verifier_matrix.py",
    "tests/test_eigiib_e16_final_closure.py",
    "tools/eigiib_e16_preservation_reference.py",
    "tools/eigiib_e16_preservation_independent.py",
    "tools/eigiib_e16_verifier_matrix.py",
    "tools/eigiib_historical_e16_a4_replay.py",
    "tools/eigiib_e16_final_closure_check.py",
]

COMPAT_WORKFLOW = '''name: E16 historical compatibility and final closure

on:
  pull_request:
    paths:
      - 'extensions/E16-*'
      - 'tools/eigiib_e16_*'
      - 'tools/eigiib_historical_e16_a4_replay.py'
      - 'schemas/eigiib-e16-*'
      - 'conformance/e16-*'
      - 'conformance/E16-*'
      - 'tests/test_eigiib_e16_*'
      - 'tests/fixtures/e16-*/**'
      - 'docs/E16-*'
      - 'EIGIIB.toml'
      - 'conformance/extension-graph.json'
      - '.github/workflows/e16-a1-preservation-intent.yml'
      - '.github/workflows/eigiib.yml'
  workflow_dispatch:

permissions:
  contents: read

env:
  PYTHONDONTWRITEBYTECODE: '1'

jobs:
  historical-compatibility:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04, macos-15, windows-2025]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          fetch-depth: 0
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1
        with:
          python-version: '3.13.14'
      - name: Exact historical E16-A4 replay
        shell: bash
        run: python tools/eigiib_historical_e16_a4_replay.py . --json > historical-e16-a4-report.json
      - name: Independent preservation verifier matrix
        shell: bash
        run: python tools/eigiib_e16_verifier_matrix.py . --json > actual-e16-a5-matrix.json
      - name: Final E16 closure compatibility
        shell: bash
        run: |
          python tools/eigiib_e16_final_closure_check.py . --history-report historical-e16-a4-report.json --matrix-report actual-e16-a5-matrix.json --json > actual-e16-a5-closure.json
          python - <<'PY2'
          import json
          from pathlib import Path
          for actual, expected in [('actual-e16-a5-matrix.json', 'tests/fixtures/e16-a5/expected-matrix-report.json'), ('actual-e16-a5-closure.json', 'tests/fixtures/e16-a5/expected-closure-report.json')]:
              if json.loads(Path(actual).read_text()) != json.loads(Path(expected).read_text()):
                  raise SystemExit(f'fixture mismatch: {actual}')
          PY2
      - name: Extension graph
        shell: bash
        run: python tools/eigiib_extension_graph_check.py . --json
      - name: Exact E16-A4 ancestry
        shell: bash
        run: git merge-base --is-ancestor b28fe74f829141232770155724620617bfb1241c HEAD
'''

STABLE_ROOT = '''# E16 — External Custody, Replication, Retention and Recovery Governance

Status: closed at `E16-A5`; stable profile `EIGIIB-E16-1.0`.

## Purpose

E16 governs the transition from a closed E15 external-object record to bounded preservation governance. It separates preservation intent, logical replica binding, placement, custody acceptance, declared failure domains, retention windows, bounded observations, independent readback, restore verification, custodian succession, migration, loss, quarantine and anti-rollback recovery.

## Principal slices

- E16-A1 preserves exact E15 and M0-A7 continuity and introduces preservation intent, custodian profiles and logical replica binding.
- E16-A2 introduces placement requests, custody acceptance, declared failure domains and bounded placement observations.
- E16-A3 introduces retention windows, boundary observations, declared-independent readback and bounded restore verification.
- E16-A4 introduces custodian succession, migration, loss, quarantine and anti-rollback recovery.
- E16-A5 closes the lineage through an independent verifier matrix, differential restore replay and a final authority freeze.

## Final closure boundary

Earlier slices remain authoritative at their exact historical heads and are replayed in isolated trees. The stable profile is admitted only when the E16-A4 replay, the frozen 20-vector matrix, the two separate-process verifier routes, canonical report agreement, the final manual gate and the 95-authority freeze are conformant.

## State separation

Gate values are `permit`, `deny`, `held`, and `unavailable`. Final matrix states are `e16-preservation-closure-verified`, `rejected`, `held`, and `unavailable`. Known negative evidence takes precedence over unavailable and held evidence.

## Nonclaims

E16 does not establish physical or legal custody transfer, real verifier or failure-domain independence, continuous retention, indefinite durability, globally trusted time, complete loss detection, complete quarantine enforcement, future restore success, external-service honesty, collusion resistance, universal verifier correctness, universal availability, universal interoperability, or external durability of the final freeze.
'''


def patch_profile() -> None:
    p = Path("EIGIIB.toml")
    text = p.read_text(encoding="utf-8")
    old = 'revision = "EIGIIB-E16-draft-1.0"'
    if old not in text:
        raise SystemExit("profile revision anchor missing")
    text = text.replace(old, 'revision = "EIGIIB-E16-1.0"', 1)
    lines = text.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("required_authorities = "))
    values = ast.literal_eval(lines[index].split("=", 1)[1].strip())
    for key in PROFILE_KEYS:
        if key not in values:
            values.append(key)
    lines[index] = "required_authorities = " + json.dumps(values)
    text = "\n".join(lines) + "\n"
    anchor = 'e16_a1_human_mastery = "docs/E16-A1-HUMAN-MASTERY-GUIDE.md"\n'
    if anchor not in text:
        raise SystemExit("profile authority anchor missing")
    insert = "".join(f'{key} = "{value}"\n' for key, value in PROFILE_KEYS.items())
    text = text.replace(anchor, anchor + insert, 1)
    gates = [
        ("e16-a2-replica-placement-boundary-review", "e16_a2_contract", "conformance/E16-A2-MANUAL-REVIEW.md"),
        ("e16-a3-retention-readback-restore-review", "e16_a3_contract", "conformance/E16-A3-MANUAL-REVIEW.md"),
        ("e16-a4-succession-recovery-review", "e16_a4_contract", "conformance/E16-A4-MANUAL-REVIEW.md"),
        ("e16-a5-final-closure-review", "e16_a5_contract", "conformance/E16-A5-MANUAL-REVIEW.md"),
    ]
    for gate_id, authority, attestation in gates:
        if f'id = "{gate_id}"' not in text:
            text += f'\n[[manual_gates]]\nid = "{gate_id}"\nstatus = "complete"\nauthority = "{authority}"\nattestation = "{attestation}"\n'
    p.write_text(text, encoding="utf-8")


def patch_graph() -> None:
    p = Path("conformance/extension-graph.json")
    graph = json.loads(p.read_text(encoding="utf-8"))
    nodes = [item for item in graph["nodes"] if item.get("id") == "E16"]
    if len(nodes) != 1:
        raise SystemExit("E16 graph cardinality")
    node = nodes[0]
    node.update({
        "theme": "complete external custody, preservation and recovery governance",
        "schema": "schemas/eigiib-e16-a5-final-closure.schema.json",
        "checker": "tools/eigiib_e16_final_closure_check.py",
        "registry_authority_key": "e16_final_closure",
        "registry": "conformance/e16-final-closure.json",
        "hardening_profiles": ["E16-A5"],
    })
    for key in PROFILE_KEYS:
        if key not in node["consumes_authorities"]:
            node["consumes_authorities"].append(key)
    node["does_not_reprove"] = [
        "E15 delivery, publication or withdrawal evidence",
        "physical or legal custody transfer",
        "real verifier or failure-domain independence",
        "continuous retention",
        "indefinite durability",
        "globally trusted time",
        "complete loss detection",
        "complete quarantine enforcement",
        "future restore success",
        "external-service honesty",
        "collusion resistance",
        "universal verifier correctness",
        "universal availability",
        "universal interoperability",
        "external durability of the final freeze",
    ]
    profiles = graph.setdefault("hardening_profiles", [])
    if not any(item.get("id") == "E16-A5" for item in profiles):
        profiles.append({
            "id": "E16-A5",
            "applies_to": "E16",
            "authority": "extensions/E16-A5-INDEPENDENT-PRESERVATION-VERIFIER-MATRIX-DIFFERENTIAL-RESTORE-REPLAY-FINAL-FREEZE.md",
            "schema": "schemas/eigiib-e16-a5-final-closure.schema.json",
            "checker": "tools/eigiib_e16_final_closure_check.py",
            "tests": ["tests/test_eigiib_e16_verifier_matrix.py", "tests/test_eigiib_e16_final_closure.py"],
        })
    p.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")


def patch_a1_test() -> None:
    p = Path("tests/test_eigiib_preservation_intent.py")
    text = p.read_text(encoding="utf-8")
    text = text.replace(
        "import copy, hashlib, importlib.util, json, shutil, sys, tempfile, unittest",
        "import copy, hashlib, importlib.util, json, shutil, subprocess, sys, tempfile, unittest",
        1,
    )
    needle = '  self.history=self.root/"history.json";'
    snippet = (
        '  for rel in ("EIGIIB.toml","conformance/extension-graph.json"):\n'
        f'   proc=subprocess.run(["git","show",f"{SOURCE_A1}:{{rel}}"],cwd=SOURCE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)\n'
        '   if proc.returncode: raise RuntimeError(proc.stderr.decode(errors="replace"))\n'
        '   dst=self.root/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(proc.stdout)\n'
    )
    if needle not in text:
        raise SystemExit("A1 test anchor missing")
    if 'subprocess.run(["git","show"' not in text:
        text = text.replace(needle, snippet + needle, 1)
    p.write_text(text, encoding="utf-8")


def patch_global_workflow() -> None:
    p = Path(".github/workflows/eigiib.yml")
    text = p.read_text(encoding="utf-8")
    pattern = re.compile(
        r"      - name: EIGIIB E16-A1 preservation-intent conformance\n.*?(?=      - name: EIGIIB M0-A2 aggregate conformance)",
        re.S,
    )
    replacement = '''      - name: Historical E16-A4 authority replay
        if: always()
        run: |
          set -o pipefail
          python tools/eigiib_historical_e16_a4_replay.py . --json | tee .eigiib-results/e16-a4-history.json
      - name: EIGIIB E16-A5 independent preservation verifier matrix
        if: always()
        run: |
          set -o pipefail
          python tools/eigiib_e16_verifier_matrix.py . --json | tee .eigiib-results/e16-a5-matrix.json
      - name: EIGIIB E16 final closure
        if: always()
        run: |
          set -o pipefail
          python tools/eigiib_e16_final_closure_check.py . --history-report .eigiib-results/e16-a4-history.json --matrix-report .eigiib-results/e16-a5-matrix.json --json | tee .eigiib-results/components/e16.json
      - name: Bind E16-A5 hardening-profile report carrier
        if: always()
        run: cp .eigiib-results/components/e16.json .eigiib-results/components/e16-a5.json
'''
    updated, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise SystemExit("global E16 step anchor mismatch")
    p.write_text(updated, encoding="utf-8")


def generate_freeze() -> None:
    paths: set[str] = set()
    for rel in [
        "conformance/e16-a1-authority-freeze.json",
        "conformance/e16-a2-authority-freeze.json",
        "conformance/e16-a3-authority-freeze.json",
        "conformance/e16-a4-authority-freeze.json",
    ]:
        for item in json.loads(Path(rel).read_text(encoding="utf-8"))["authorities"]:
            paths.add(item["path"])
    paths.update(A5_PATHS)
    if len(paths) != 95:
        raise SystemExit(f"expected 95 final authorities, got {len(paths)}")
    items = []
    for rel in sorted(paths):
        p = Path(rel)
        if not p.is_file():
            raise SystemExit(f"missing final authority: {rel}")
        raw = p.read_bytes()
        items.append({"path": rel, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    data = {
        "standard": "EIGIIB-E16-A5-FREEZE-1.0",
        "status": "final-frozen",
        "profile_revision": "EIGIIB-E16-1.0",
        "source_e16_a4_commit": SOURCE_A4,
        "authority_count": 95,
        "authorities": items,
    }
    Path("conformance/e16-a5-authority-freeze.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def stage_workflows() -> None:
    d = Path(".e16a5-final-workflows")
    d.mkdir(exist_ok=True)
    for name in ["e16-a1-preservation-intent.yml", "eigiib.yml", "e16-a5-final-closure.yml"]:
        (d / name).write_bytes((Path(".github/workflows") / name).read_bytes())


def main() -> None:
    patch_profile()
    patch_graph()
    Path("extensions/E16-EXTERNAL-CUSTODY-REPLICATION-RETENTION-RECOVERY-GOVERNANCE.md").write_text(STABLE_ROOT, encoding="utf-8")
    patch_a1_test()
    Path(".github/workflows/e16-a1-preservation-intent.yml").write_text(COMPAT_WORKFLOW, encoding="utf-8")
    patch_global_workflow()
    generate_freeze()
    stage_workflows()

if __name__ == "__main__":
    main()
