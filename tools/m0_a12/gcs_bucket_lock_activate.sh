#!/usr/bin/env bash
set -euo pipefail

EXPECTED_SHA256="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
EXPECTED_BYTES="985664"
MODE="${M0_A12_MODE:-plan}"
ARTIFACT="${M0_A12_ARTIFACT:-eigiib-e16-1.0-stable-bundle.tar.gz}"
PROJECT="${M0_A12_GCP_PROJECT:-}"
BUCKET="${M0_A12_GCS_BUCKET:-}"
LOCATION="${M0_A12_GCS_LOCATION:-}"
RETENTION_PERIOD="${M0_A12_GCS_RETENTION_PERIOD:-30d}"
OBJECT_NAME="${M0_A12_OBJECT_KEY:-eigiib-e16-1.0-stable-bundle.tar.gz}"
AUTHORIZED_CONFIG="${M0_A12_GCLOUD_AUTHORIZED_CONFIGURATION:-}"
PRIVILEGED_CONFIG="${M0_A12_GCLOUD_PRIVILEGED_CONFIGURATION:-}"
OUT="${M0_A12_OUTPUT_DIR:-m0-a12-gcs-evidence}"

fail() { printf 'M0-A12 GCS: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

need gcloud
need python
need sha256sum
[[ -f "$ARTIFACT" ]] || fail "artifact not found: $ARTIFACT"
[[ "$(wc -c <"$ARTIFACT" | tr -d ' ')" == "$EXPECTED_BYTES" ]] || fail "artifact byte count mismatch"
[[ "$(sha256sum "$ARTIFACT" | awk '{print $1}')" == "$EXPECTED_SHA256" ]] || fail "artifact SHA-256 mismatch"

if [[ "$MODE" != "execute" ]]; then
  cat <<EOF
M0-A12 Google Cloud activation plan only.
Required execution variables:
  M0_A12_MODE=execute
  M0_A12_GCP_PROJECT=<project id>
  M0_A12_GCS_BUCKET=<globally unique bucket>
  M0_A12_GCS_LOCATION=<location>
  M0_A12_GCLOUD_AUTHORIZED_CONFIGURATION=<delete-capable configuration>
  M0_A12_GCLOUD_PRIVILEGED_CONFIGURATION=<privileged configuration>
  M0_A12_GCS_RETENTION_PERIOD=<duration>
This operation irreversibly locks a Cloud Storage bucket retention policy.
No external claim is produced in plan mode.
EOF
  exit 0
fi

[[ "${M0_A12_CONFIRM_IRREVERSIBLE_LOCK:-}" == "I_UNDERSTAND_BUCKET_LOCK_IS_IRREVERSIBLE" ]] \
  || fail "irreversible lock confirmation missing"
[[ -n "$PROJECT" && -n "$BUCKET" && -n "$LOCATION" ]] || fail "project, bucket and location are required"
[[ -n "$AUTHORIZED_CONFIG" && -n "$PRIVILEGED_CONFIG" ]] || fail "two gcloud configurations are required"
[[ "$AUTHORIZED_CONFIG" != "$PRIVILEGED_CONFIG" ]] || fail "authorized and privileged configurations must be distinct"

mkdir -p "$OUT/raw" "$OUT/readback"
g_auth() { gcloud --quiet --configuration="$AUTHORIZED_CONFIG" "$@"; }
g_priv() { gcloud --quiet --configuration="$PRIVILEGED_CONFIG" "$@"; }

g_priv storage buckets create "gs://$BUCKET" --project="$PROJECT" --location="$LOCATION" \
  --uniform-bucket-level-access --public-access-prevention >"$OUT/raw/create-bucket.txt"
g_priv storage buckets update "gs://$BUCKET" --retention-period="$RETENTION_PERIOD" \
  >"$OUT/raw/set-retention.txt"
g_priv storage buckets describe "gs://$BUCKET" --format=json >"$OUT/raw/bucket-before-lock.json"
g_priv storage buckets update "gs://$BUCKET" --lock-retention-period >"$OUT/raw/lock-retention.txt"
g_priv storage buckets describe "gs://$BUCKET" --format=json >"$OUT/raw/bucket-after-lock.json"

g_auth storage cp "$ARTIFACT" "gs://$BUCKET/$OBJECT_NAME" --no-clobber \
  >"$OUT/raw/upload.txt"
g_auth storage objects describe "gs://$BUCKET/$OBJECT_NAME" --format=json \
  >"$OUT/raw/object-describe.json"

GENERATION="$(python - "$OUT/raw/object-describe.json" <<'PY'
import json, sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
generation=value.get("generation")
if generation is None:
    raise SystemExit("missing generation")
print(generation)
PY
)"
printf '%s\n' "$GENERATION" >"$OUT/raw/object-generation.txt"

g_auth storage cp "gs://$BUCKET/$OBJECT_NAME#$GENERATION" "$OUT/readback/$OBJECT_NAME" \
  >"$OUT/raw/readback.txt"
[[ "$(wc -c <"$OUT/readback/$OBJECT_NAME" | tr -d ' ')" == "$EXPECTED_BYTES" ]] || fail "readback byte count mismatch"
[[ "$(sha256sum "$OUT/readback/$OBJECT_NAME" | awk '{print $1}')" == "$EXPECTED_SHA256" ]] || fail "readback SHA-256 mismatch"

attempt_delete() {
  local label="$1"; shift
  local log="$OUT/raw/delete-$label.log"
  set +e
  "$@" storage rm "gs://$BUCKET/$OBJECT_NAME#$GENERATION" >"$log" 2>&1
  local rc=$?
  set -e
  (( rc != 0 )) || fail "retention failure: $label deletion unexpectedly succeeded"
}
attempt_delete authorized g_auth
attempt_delete privileged g_priv

g_auth storage objects describe "gs://$BUCKET/$OBJECT_NAME#$GENERATION" --format=json \
  >"$OUT/raw/object-after-delete-attempts.json"

cat >"$OUT/activation-summary.json" <<EOF
{
  "providerProfile": "gcp-cloud-storage-bucket-lock",
  "project": "$PROJECT",
  "bucket": "$BUCKET",
  "location": "$LOCATION",
  "objectName": "$OBJECT_NAME",
  "objectVersionId": "$GENERATION",
  "artifactSha256": "$EXPECTED_SHA256",
  "artifactBytes": $EXPECTED_BYTES,
  "retentionPeriod": "$RETENTION_PERIOD",
  "status": "raw-evidence-captured-not-yet-attested"
}
EOF
printf 'M0-A12 GCS raw evidence written to %s\n' "$OUT"
