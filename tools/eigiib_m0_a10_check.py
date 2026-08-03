#!/usr/bin/env python3
"""EIGIIB M0-A10 structural and cryptographic conformance checker."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

STANDARD = "EIGIIB-M0-A10-1.0"
REPORT_STANDARD = "EIGIIB-M0-A10-REPORT-1.0"
M0_A9_HEAD = "af028b4b99c216cffb7764571e3e97db29d76635"
STABLE_E16_HEAD = "fc3f8402bfbe447227f5777bad92b620c7bcb350"
BUNDLE_NAME = "eigiib-e16-1.0-stable-bundle.tar.gz"
BUNDLE_BYTES = 985664
BUNDLE_SHA256 = "96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
MANIFEST_PATH = "conformance/m0-a10-stable-bundle-manifest.json"
MANIFEST_BYTES = 1058
MANIFEST_SHA256 = "25c04438df49d7261cf9814142dc0dd575b278ba65e05bc244b13b35d16407a9"
SIGNATURE_PATH = "conformance/m0-a10-stable-bundle-manifest.sig"
SIGNATURE_BYTES = 64
SIGNATURE_SHA256 = "90925a270871949faf2079eb74321200b0f2eae873a4bc22c9cfac6ccee0a4e4"
PUBLIC_KEY_PATH = "conformance/m0-a10-publisher-public-key.pem"
PUBLIC_KEY_BYTES = 113
PUBLIC_KEY_SHA256 = "27116e2e7771cc300b2d2acbc205fd0992c23b8ebec4fe5b5b58023f0aa5382e"
PUBLIC_SPKI_SHA256 = "b28aff5df510ff86192b0df96f9712ccbe36fd22265e493a0a6d098dfc60504a"
OCI_MANIFEST_PATH = "conformance/m0-a10-oci-manifest.json"
OCI_MANIFEST_BYTES = 1557
OCI_MANIFEST_DIGEST = "sha256:8d3fba5d596d668ea000a768d524e35003e08f95162b633d8af7922449b13c88"
EVIDENCE_PATH = "conformance/m0-a10-live-publication-evidence.json"
CLEANUP_PATH = "conformance/m0-a10-ops-cleanup-record.json"
AUTHORITY_PATH = "conformance/m0-a10-dual-channel-publication.json"
FREEZE_PATH = "conformance/m0-a10-authority-freeze.json"
PROMOTION_PATH = "conformance/m0-a9-promotion-readiness.json"

REQUIRED_OPERATIONS = [
    "construct-deterministic-bundle-from-exact-stable-e16-head",
    "bind-signed-manifest-to-exact-bundle-and-source-head",
    "publish-exact-bundle-through-github-release",
    "publish-exact-bundle-through-oci-registry",
    "capture-authenticated-and-public-readback",
    "restore-and-compare-from-each-named-channel",
]
ROUTES = [
    "github-release-authenticated",
    "github-release-public",
    "oci-registry-authenticated",
    "oci-registry-public",
]
EVIDENCE_ROUTES = ["release-auth", "release-public", "oci-auth", "oci-public"]
NONCLAIMS = [
    "production-release-authorization",
    "future-availability",
    "continuous-retention",
    "indefinite-durability",
    "provider-independence",
    "correlated-failure-resistance",
    "administrative-deletion-prevention",
    "universal-interoperability",
    "e17-adoption",
]
EXPECTED_OBJECTS = {
    BUNDLE_NAME: (BUNDLE_BYTES, BUNDLE_SHA256),
    "eigiib-e16-1.0-stable-bundle-manifest.json": (MANIFEST_BYTES, MANIFEST_SHA256),
    "eigiib-e16-1.0-stable-bundle-manifest.sig": (SIGNATURE_BYTES, SIGNATURE_SHA256),
    "eigiib-m0-a10-publisher-ed25519-public.pem": (PUBLIC_KEY_BYTES, PUBLIC_KEY_SHA256),
}


def _read_json(root: Path, rel: str, findings: list[str]) -> dict[str, Any]:
    path = root / rel
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        findings.append(f"M0A10.FILE.MISSING:{rel}")
        return {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        findings.append(f"M0A10.JSON.INVALID:{rel}")
        return {}
    if not isinstance(value, dict):
        findings.append(f"M0A10.JSON.OBJECT:{rel}")
        return {}
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expect(condition: bool, code: str, findings: list[str]) -> None:
    if not condition:
        findings.append(code)


def _identity(root: Path, rel: str, size: int, digest: str, findings: list[str]) -> None:
    path = root / rel
    if not path.is_file():
        findings.append(f"M0A10.FILE.MISSING:{rel}")
        return
    _expect(path.stat().st_size == size, f"M0A10.FILE.BYTES:{rel}", findings)
    _expect(_sha256(path) == digest, f"M0A10.FILE.SHA256:{rel}", findings)


def _verify_signature(root: Path, findings: list[str]) -> None:
    manifest = root / MANIFEST_PATH
    signature = root / SIGNATURE_PATH
    public_key = root / PUBLIC_KEY_PATH
    try:
        der = subprocess.check_output(
            ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
            stderr=subprocess.STDOUT,
        )
        _expect(hashlib.sha256(der).hexdigest() == PUBLIC_SPKI_SHA256, "M0A10.PUBLIC_KEY.SPKI", findings)
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                "-inkey", str(public_key), "-in", str(manifest), "-sigfile", str(signature),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        _expect(result.returncode == 0, "M0A10.SIGNATURE.INVALID", findings)
    except (FileNotFoundError, subprocess.CalledProcessError):
        findings.append("M0A10.OPENSSL.UNAVAILABLE")


def _check_promotion(root: Path, findings: list[str]) -> None:
    doc = _read_json(root, PROMOTION_PATH, findings)
    _expect(doc.get("profile_revision") == "EIGIIB-E16-1.0", "M0A10.PROMOTION.PROFILE", findings)
    candidates = {item.get("id"): item for item in doc.get("candidates", []) if isinstance(item, dict)}
    a10 = candidates.get("M0-A10", {})
    e17 = candidates.get("E17", {})
    _expect(a10.get("decision") == "ready-for-bounded-implementation", "M0A10.PROMOTION.DECISION", findings)
    _expect(a10.get("required_new_operations") == REQUIRED_OPERATIONS, "M0A10.PROMOTION.OPERATIONS", findings)
    _expect(a10.get("permitted_result") == "bounded-external-publication-and-readback-verified", "M0A10.PROMOTION.RESULT", findings)
    _expect(a10.get("forbidden_result") == "future-or-indefinite-durability-established", "M0A10.PROMOTION.FORBIDDEN", findings)
    _expect(e17.get("decision") == "not-ready-for-adoption", "M0A10.E17.PREMATURE", findings)
    _expect(doc.get("automatic_adoption") is False, "M0A10.PROMOTION.AUTOMATIC", findings)


def _check_authority(root: Path, findings: list[str]) -> dict[str, Any]:
    doc = _read_json(root, AUTHORITY_PATH, findings)
    _expect(doc.get("standard") == STANDARD, "M0A10.AUTHORITY.STANDARD", findings)
    _expect(doc.get("status") == "bounded-external-publication-and-readback-verified", "M0A10.AUTHORITY.STATUS", findings)
    source = doc.get("source", {})
    _expect(source.get("m0A9Head") == M0_A9_HEAD, "M0A10.SOURCE.M0A9", findings)
    _expect(source.get("stableE16Branch") == "stable/eigiib-e16-1.0", "M0A10.SOURCE.BRANCH", findings)
    _expect(source.get("stableE16Head") == STABLE_E16_HEAD, "M0A10.SOURCE.E16", findings)
    _expect(source.get("profileRevision") == "EIGIIB-E16-1.0", "M0A10.SOURCE.PROFILE", findings)
    _expect(doc.get("requiredOperations") == REQUIRED_OPERATIONS, "M0A10.AUTHORITY.OPERATIONS", findings)
    _expect(doc.get("readbackRoutes") == ROUTES, "M0A10.AUTHORITY.ROUTES", findings)
    _expect(doc.get("evidencePath") == EVIDENCE_PATH, "M0A10.AUTHORITY.EVIDENCE", findings)
    _expect(doc.get("cleanupRecordPath") == CLEANUP_PATH, "M0A10.AUTHORITY.CLEANUP", findings)
    _expect(doc.get("nonclaims") == NONCLAIMS, "M0A10.AUTHORITY.NONCLAIMS", findings)
    claims = doc.get("claims", {})
    for key in [
        "crossChannelContentIdentity",
        "currentAuthenticatedAndPublicReadback",
        "currentExactRestore",
        "currentNamedChannelPublication",
    ]:
        _expect(claims.get(key) == "established", f"M0A10.CLAIM.{key}", findings)
    successor = doc.get("naturalSuccessor", {})
    _expect(successor.get("id") == "E17", "M0A10.SUCCESSOR.ID", findings)
    _expect(successor.get("decision") == "not-ready-for-adoption", "M0A10.SUCCESSOR.DECISION", findings)
    bundle = doc.get("bundle", {})
    _expect(bundle.get("name") == BUNDLE_NAME, "M0A10.BUNDLE.NAME", findings)
    _expect(bundle.get("bytes") == BUNDLE_BYTES, "M0A10.BUNDLE.BYTES", findings)
    _expect(bundle.get("sha256") == BUNDLE_SHA256, "M0A10.BUNDLE.SHA256", findings)
    _expect(bundle.get("manifestSha256") == MANIFEST_SHA256, "M0A10.BUNDLE.MANIFEST", findings)
    _expect(bundle.get("signatureSha256") == SIGNATURE_SHA256, "M0A10.BUNDLE.SIGNATURE", findings)
    _expect(bundle.get("publicKeySha256") == PUBLIC_KEY_SHA256, "M0A10.BUNDLE.PUBLIC_KEY", findings)
    _expect(bundle.get("signerBoundary") == "ephemeral-publication-integrity-key-not-production-release-authority", "M0A10.SIGNER.BOUNDARY", findings)
    release = doc.get("channels", {}).get("githubRelease", {})
    _expect(release == {
        "assetCount": 4,
        "draft": False,
        "id": 364532554,
        "immutable": False,
        "prerelease": True,
        "repository": "Nico59000/EIGIIB-norm",
        "tag": "eigiib-m0-a10-e16-stable-v1",
    }, "M0A10.RELEASE.IDENTITY", findings)
    oci = doc.get("channels", {}).get("ociRegistry", {})
    _expect(oci == {
        "manifestBytes": OCI_MANIFEST_BYTES,
        "manifestDigest": OCI_MANIFEST_DIGEST,
        "manifestPath": OCI_MANIFEST_PATH,
        "repository": "ghcr.io/nico59000/eigiib-norm-p1-a16",
        "tag": "m0-a10-e16-stable-v1",
    }, "M0A10.OCI.IDENTITY", findings)
    return doc


def _check_manifest(root: Path, findings: list[str]) -> None:
    _identity(root, MANIFEST_PATH, MANIFEST_BYTES, MANIFEST_SHA256, findings)
    _identity(root, SIGNATURE_PATH, SIGNATURE_BYTES, SIGNATURE_SHA256, findings)
    _identity(root, PUBLIC_KEY_PATH, PUBLIC_KEY_BYTES, PUBLIC_KEY_SHA256, findings)
    manifest = _read_json(root, MANIFEST_PATH, findings)
    _expect(manifest.get("standard") == "EIGIIB-M0-A10-BUNDLE-MANIFEST-1.0", "M0A10.MANIFEST.STANDARD", findings)
    _expect(manifest.get("source") == {
        "commit": STABLE_E16_HEAD,
        "profileRevision": "EIGIIB-E16-1.0",
        "repository": "Nico59000/EIGIIB-norm",
        "stableBranch": "stable/eigiib-e16-1.0",
    }, "M0A10.MANIFEST.SOURCE", findings)
    _expect(manifest.get("bundle") == {
        "bytes": BUNDLE_BYTES,
        "mediaType": "application/vnd.eigiib.e16.stable-bundle.v1+gzip",
        "name": BUNDLE_NAME,
        "sha256": BUNDLE_SHA256,
    }, "M0A10.MANIFEST.BUNDLE", findings)
    signature = manifest.get("signature", {})
    _expect(signature.get("algorithm") == "Ed25519", "M0A10.MANIFEST.ALGORITHM", findings)
    _expect(signature.get("publicKeyAsset") == "eigiib-m0-a10-publisher-ed25519-public.pem", "M0A10.MANIFEST.PUBLIC_KEY", findings)
    _expect(signature.get("publicSpkiSha256") == PUBLIC_SPKI_SHA256, "M0A10.MANIFEST.SPKI", findings)
    _expect(signature.get("authorityBoundary") == "ephemeral-publication-integrity-key-not-production-release-authority", "M0A10.MANIFEST.BOUNDARY", findings)
    claims = manifest.get("claims", {})
    _expect(claims.get("exactStableSourceBinding") == "established", "M0A10.MANIFEST.SOURCE_CLAIM", findings)
    _expect(claims.get("bundleContentIdentity") == "established", "M0A10.MANIFEST.BUNDLE_CLAIM", findings)
    for key in ["productionReleaseAuthorization", "futureAvailability", "indefiniteDurability"]:
        _expect(claims.get(key) == "not-claimed", f"M0A10.MANIFEST.NONCLAIM.{key}", findings)


def _check_oci(root: Path, findings: list[str]) -> None:
    _identity(root, OCI_MANIFEST_PATH, OCI_MANIFEST_BYTES, OCI_MANIFEST_DIGEST.split(":", 1)[1], findings)
    doc = _read_json(root, OCI_MANIFEST_PATH, findings)
    _expect(doc.get("schemaVersion") == 2, "M0A10.OCI.SCHEMA", findings)
    _expect(doc.get("mediaType") == "application/vnd.oci.image.manifest.v1+json", "M0A10.OCI.MEDIA", findings)
    _expect(doc.get("artifactType") == "application/vnd.eigiib.m0-a10.e16-stable-bundle.v1", "M0A10.OCI.ARTIFACT", findings)
    layers = doc.get("layers", [])
    _expect(len(layers) == 4, "M0A10.OCI.LAYER_COUNT", findings)
    observed = {}
    for layer in layers:
        if isinstance(layer, dict):
            title = layer.get("annotations", {}).get("org.opencontainers.image.title")
            if isinstance(title, str):
                observed[title] = (layer.get("size"), layer.get("digest"))
    expected = {name: (size, f"sha256:{digest}") for name, (size, digest) in EXPECTED_OBJECTS.items()}
    _expect(observed == expected, "M0A10.OCI.LAYERS", findings)
    annotations = doc.get("annotations", {})
    _expect(annotations.get("org.opencontainers.image.revision") == STABLE_E16_HEAD, "M0A10.OCI.REVISION", findings)
    _expect(annotations.get("org.opencontainers.image.source") == "https://github.com/Nico59000/EIGIIB-norm", "M0A10.OCI.SOURCE", findings)


def _check_evidence(root: Path, findings: list[str]) -> dict[str, Any]:
    doc = _read_json(root, EVIDENCE_PATH, findings)
    _expect(doc.get("standard") == "EIGIIB-M0-A10-LIVE-PUBLICATION-EVIDENCE-1.0", "M0A10.EVIDENCE.STANDARD", findings)
    _expect(doc.get("status") == "bounded-external-publication-and-readback-verified", "M0A10.EVIDENCE.STATUS", findings)
    _expect(doc.get("source") == {
        "commit": STABLE_E16_HEAD,
        "profileRevision": "EIGIIB-E16-1.0",
        "repository": "Nico59000/EIGIIB-norm",
        "stableBranch": "stable/eigiib-e16-1.0",
    }, "M0A10.EVIDENCE.SOURCE", findings)
    _expect(doc.get("bundle") == {"bytes": BUNDLE_BYTES, "name": BUNDLE_NAME, "sha256": BUNDLE_SHA256}, "M0A10.EVIDENCE.BUNDLE", findings)
    release = doc.get("githubRelease", {})
    _expect(release.get("id") == 364532554, "M0A10.EVIDENCE.RELEASE_ID", findings)
    _expect(release.get("tag") == "eigiib-m0-a10-e16-stable-v1", "M0A10.EVIDENCE.RELEASE_TAG", findings)
    _expect(release.get("draft") is False and release.get("prerelease") is True, "M0A10.EVIDENCE.RELEASE_STATE", findings)
    _expect(release.get("assetCount") == 4, "M0A10.EVIDENCE.RELEASE_ASSETS", findings)
    for key in ["authenticatedReadback", "publicReadback", "exactRestore"]:
        _expect(release.get(key) == "conformant", f"M0A10.EVIDENCE.RELEASE_{key}", findings)
    oci = doc.get("ociRegistry", {})
    _expect(oci.get("repository") == "ghcr.io/nico59000/eigiib-norm-p1-a16", "M0A10.EVIDENCE.OCI_REPO", findings)
    _expect(oci.get("tag") == "m0-a10-e16-stable-v1", "M0A10.EVIDENCE.OCI_TAG", findings)
    _expect(oci.get("manifestDigest") == OCI_MANIFEST_DIGEST, "M0A10.EVIDENCE.OCI_DIGEST", findings)
    _expect(oci.get("manifestBytes") == OCI_MANIFEST_BYTES, "M0A10.EVIDENCE.OCI_BYTES", findings)
    for key in ["authenticatedReadback", "publicReadback", "exactRestore"]:
        _expect(oci.get(key) == "conformant", f"M0A10.EVIDENCE.OCI_{key}", findings)
    routes = doc.get("routes", {})
    _expect(sorted(routes) == sorted(EVIDENCE_ROUTES), "M0A10.EVIDENCE.ROUTES", findings)
    for route in EVIDENCE_ROUTES:
        route_data = routes.get(route, {})
        expected = {name: {"bytes": size, "sha256": digest} for name, (size, digest) in EXPECTED_OBJECTS.items()}
        _expect(route_data == expected, f"M0A10.EVIDENCE.ROUTE:{route}", findings)
    cross = doc.get("crossChannel", {})
    for key in ["bundleByteIdentity", "manifestByteIdentity", "signatureByteIdentity", "publicKeyByteIdentity"]:
        _expect(cross.get(key) == "conformant", f"M0A10.EVIDENCE.CROSS:{key}", findings)
    claims = doc.get("claims", {})
    for key in ["currentNamedChannelPublication", "currentAuthenticatedAndPublicReadback", "currentExactRestore"]:
        _expect(claims.get(key) == "established", f"M0A10.EVIDENCE.CLAIM:{key}", findings)
    for key in ["productionReleaseAuthorization", "futureAvailability", "indefiniteDurability", "providerIndependence"]:
        _expect(claims.get(key) == "not-claimed", f"M0A10.EVIDENCE.NONCLAIM:{key}", findings)
    return doc


def _check_cleanup(root: Path, findings: list[str]) -> dict[str, Any]:
    doc = _read_json(root, CLEANUP_PATH, findings)
    _expect(doc.get("standard") == "EIGIIB-M0-A10-OPS-CLEANUP-1.0", "M0A10.CLEANUP.STANDARD", findings)
    _expect(doc.get("status") == "purged-or-absent", "M0A10.CLEANUP.STATUS", findings)
    _expect(doc.get("deletedRunIds") == [30858788022, 30858972197], "M0A10.CLEANUP.RUNS", findings)
    _expect(doc.get("matchingPullRequests") == [], "M0A10.CLEANUP.PRS", findings)
    objects = {item.get("name"): item for item in doc.get("objects", []) if isinstance(item, dict)}
    expected_names = {"ops/m0-a9-actions-cleanup-once", "ops/m0-a9-actions-cleanup-exact"}
    _expect(set(objects) == expected_names, "M0A10.CLEANUP.OBJECTS", findings)
    for name in expected_names:
        item = objects.get(name, {})
        _expect(item.get("branchRefPresent") is False, f"M0A10.CLEANUP.REF:{name}", findings)
        _expect(item.get("pullRequestCount") == 0, f"M0A10.CLEANUP.PR:{name}", findings)
        _expect(item.get("compareEndpointExpected") == "404-ref-absent", f"M0A10.CLEANUP.COMPARE:{name}", findings)
    method = doc.get("method", {})
    _expect(method.get("runRemoval") == "DELETE /repos/{owner}/{repo}/actions/runs/{run_id}", "M0A10.CLEANUP.METHOD.RUN", findings)
    _expect(method.get("branchRemoval") == "DELETE /repos/{owner}/{repo}/git/refs/heads/{encoded-ref}", "M0A10.CLEANUP.METHOD.REF", findings)
    _expect(method.get("compareInterpretation") == "404 is the expected result after the compared head ref is deleted", "M0A10.CLEANUP.METHOD.COMPARE", findings)
    return doc


def _check_freeze(root: Path, findings: list[str]) -> int:
    doc = _read_json(root, FREEZE_PATH, findings)
    _expect(doc.get("standard") == "EIGIIB-M0-A10-AUTHORITY-FREEZE-1.0", "M0A10.FREEZE.STANDARD", findings)
    _expect(doc.get("status") == "self-excluding-authority-freeze", "M0A10.FREEZE.STATUS", findings)
    _expect(doc.get("source_head") == M0_A9_HEAD, "M0A10.FREEZE.SOURCE", findings)
    _expect(doc.get("excluded_path") == FREEZE_PATH, "M0A10.FREEZE.EXCLUDED", findings)
    authorities = doc.get("authorities", [])
    _expect(isinstance(authorities, list), "M0A10.FREEZE.AUTHORITIES", findings)
    paths = [item.get("path") for item in authorities if isinstance(item, dict)]
    _expect(len(paths) == len(set(paths)), "M0A10.FREEZE.DUPLICATE", findings)
    _expect(FREEZE_PATH not in paths, "M0A10.FREEZE.SELF", findings)
    _expect(doc.get("authority_count") == len(authorities), "M0A10.FREEZE.COUNT", findings)
    for item in authorities:
        if not isinstance(item, dict):
            findings.append("M0A10.FREEZE.ITEM")
            continue
        rel = item.get("path")
        if not isinstance(rel, str):
            findings.append("M0A10.FREEZE.PATH")
            continue
        path = root / rel
        if not path.is_file():
            findings.append(f"M0A10.FREEZE.MISSING:{rel}")
            continue
        _expect(path.stat().st_size == item.get("bytes"), f"M0A10.FREEZE.BYTES:{rel}", findings)
        _expect(_sha256(path) == item.get("sha256"), f"M0A10.FREEZE.SHA256:{rel}", findings)
    return len(authorities)


def evaluate(root: Path, *, verify_signature: bool = True) -> dict[str, Any]:
    root = root.resolve()
    findings: list[str] = []
    _check_promotion(root, findings)
    _check_authority(root, findings)
    _check_manifest(root, findings)
    _check_oci(root, findings)
    evidence = _check_evidence(root, findings)
    cleanup = _check_cleanup(root, findings)
    if verify_signature:
        _verify_signature(root, findings)
    authority_count = _check_freeze(root, findings)
    report = {
        "standard": REPORT_STANDARD,
        "tool": "eigiib_m0_a10_check.py",
        "tool_version": "0.1.0",
        "structural_result": "conformant" if not findings else "non-conformant",
        "status": "bounded-external-publication-and-readback-verified" if not findings else "rejected",
        "source_m0_a9_head": M0_A9_HEAD,
        "source_stable_e16_head": STABLE_E16_HEAD,
        "bundle": {"bytes": BUNDLE_BYTES, "sha256": BUNDLE_SHA256},
        "github_release_id": 364532554,
        "oci_manifest_digest": OCI_MANIFEST_DIGEST,
        "readback_route_count": len(EVIDENCE_ROUTES),
        "restored_object_observation_count": len(EVIDENCE_ROUTES) * len(EXPECTED_OBJECTS),
        "cleanup_deleted_run_count": len(cleanup.get("deletedRunIds", [])) if isinstance(cleanup, dict) else 0,
        "authority_count": authority_count,
        "observation_workflow_run_id": evidence.get("observation", {}).get("workflowRunId") if isinstance(evidence, dict) else None,
        "findings": sorted(set(findings)),
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--skip-signature-crypto", action="store_true")
    args = parser.parse_args(argv)
    report = evaluate(Path(args.root), verify_signature=not args.skip_signature_crypto)
    payload = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    if args.json or not args.output:
        sys.stdout.write(payload)
    return 0 if report["structural_result"] == "conformant" else 1


if __name__ == "__main__":
    raise SystemExit(main())
