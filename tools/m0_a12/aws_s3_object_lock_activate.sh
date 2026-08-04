#!/usr/bin/env bash
set -euo pipefail

EXPECTED_SHA256="96332827d36ecc360b9d4cf82947d44d161747afc40e3bb37cecc64837c6cfde"
EXPECTED_BYTES="985664"
MODE="${M0_A12_MODE:-plan}"
ARTIFACT="${M0_A12_ARTIFACT:-eigiib-e16-1.0-stable-bundle.tar.gz}"
BUCKET="${M0_A12_AWS_BUCKET:-}"
REGION="${M0_A12_AWS_REGION:-}"
RETENTION_DAYS="${M0_A12_RETENTION_DAYS:-30}"
OBJECT_KEY="${M0_A12_OBJECT_KEY:-eigiib-e16-1.0-stable-bundle.tar.gz}"
AUTHORIZED_PROFILE="${M0_A12_AWS_AUTHORIZED_PROFILE:-}"
PRIVILEGED_PROFILE="${M0_A12_AWS_PRIVILEGED_PROFILE:-}"
OUT="${M0_A12_OUTPUT_DIR:-m0-a12-aws-evidence}"

fail() { printf 'M0-A12 AWS: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

need aws
need python
need sha256sum
[[ -f "$ARTIFACT" ]] || fail "artifact not found: $ARTIFACT"
[[ "$(wc -c <"$ARTIFACT" | tr -d ' ')" == "$EXPECTED_BYTES" ]] || fail "artifact byte count mismatch"
[[ "$(sha256sum "$ARTIFACT" | awk '{print $1}')" == "$EXPECTED_SHA256" ]] || fail "artifact SHA-256 mismatch"
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] && (( RETENTION_DAYS >= 1 )) || fail "retention days must be a positive integer"

if [[ "$MODE" != "execute" ]]; then
  cat <<EOF
M0-A12 AWS activation plan only.
Required execution variables:
  M0_A12_MODE=execute
  M0_A12_AWS_BUCKET=<globally unique bucket>
  M0_A12_AWS_REGION=<AWS region>
  M0_A12_AWS_AUTHORIZED_PROFILE=<delete-capable principal profile>
  M0_A12_AWS_PRIVILEGED_PROFILE=<privileged administrator profile>
  M0_A12_RETENTION_DAYS=<positive integer>
This operation creates an Object-Lock bucket and applies COMPLIANCE retention.
No external claim is produced in plan mode.
EOF
  exit 0
fi

[[ "${M0_A12_CONFIRM_IRREVERSIBLE_LOCK:-}" == "I_UNDERSTAND_COMPLIANCE_RETENTION_IS_NON_BYPASSABLE" ]] \
  || fail "irreversible lock confirmation missing"
[[ -n "$BUCKET" && -n "$REGION" ]] || fail "bucket and region are required"
[[ -n "$AUTHORIZED_PROFILE" && -n "$PRIVILEGED_PROFILE" ]] || fail "two profile names are required"
[[ "$AUTHORIZED_PROFILE" != "$PRIVILEGED_PROFILE" ]] || fail "authorized and privileged profiles must be distinct"

mkdir -p "$OUT/raw" "$OUT/readback"
aws_auth() { AWS_PROFILE="$AUTHORIZED_PROFILE" aws --region "$REGION" --no-cli-pager "$@"; }
aws_priv() { AWS_PROFILE="$PRIVILEGED_PROFILE" aws --region "$REGION" --no-cli-pager "$@"; }

if [[ "$REGION" == "us-east-1" ]]; then
  aws_priv s3api create-bucket --bucket "$BUCKET" --object-lock-enabled-for-bucket \
    >"$OUT/raw/create-bucket.json"
else
  aws_priv s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=$REGION" \
    --object-lock-enabled-for-bucket >"$OUT/raw/create-bucket.json"
fi

aws_priv s3api put-object-lock-configuration --bucket "$BUCKET" \
  --object-lock-configuration "{\"ObjectLockEnabled\":\"Enabled\",\"Rule\":{\"DefaultRetention\":{\"Mode\":\"COMPLIANCE\",\"Days\":$RETENTION_DAYS}}}" \
  >"$OUT/raw/put-object-lock-configuration.json"

aws_auth s3api put-object --bucket "$BUCKET" --key "$OBJECT_KEY" --body "$ARTIFACT" \
  --checksum-algorithm SHA256 >"$OUT/raw/put-object.json"

VERSION_ID="$(python - "$OUT/raw/put-object.json" <<'PY'
import json, sys
value=json.load(open(sys.argv[1], encoding="utf-8"))
version=value.get("VersionId")
if not version:
    raise SystemExit("missing VersionId")
print(version)
PY
)"
printf '%s\n' "$VERSION_ID" >"$OUT/raw/object-version-id.txt"

aws_auth s3api get-object-retention --bucket "$BUCKET" --key "$OBJECT_KEY" --version-id "$VERSION_ID" \
  >"$OUT/raw/get-object-retention.json"
aws_auth s3api head-object --bucket "$BUCKET" --key "$OBJECT_KEY" --version-id "$VERSION_ID" \
  >"$OUT/raw/head-object.json"
aws_auth s3api get-object --bucket "$BUCKET" --key "$OBJECT_KEY" --version-id "$VERSION_ID" \
  "$OUT/readback/$OBJECT_KEY" >"$OUT/raw/get-object.json"

[[ "$(wc -c <"$OUT/readback/$OBJECT_KEY" | tr -d ' ')" == "$EXPECTED_BYTES" ]] || fail "readback byte count mismatch"
[[ "$(sha256sum "$OUT/readback/$OBJECT_KEY" | awk '{print $1}')" == "$EXPECTED_SHA256" ]] || fail "readback SHA-256 mismatch"

attempt_delete() {
  local label="$1"; shift
  local log="$OUT/raw/delete-$label.log"
  set +e
  "$@" s3api delete-object --bucket "$BUCKET" --key "$OBJECT_KEY" --version-id "$VERSION_ID" >"$log" 2>&1
  local rc=$?
  set -e
  (( rc != 0 )) || fail "retention failure: $label deletion unexpectedly succeeded"
}
attempt_delete authorized aws_auth
attempt_delete privileged aws_priv

aws_auth s3api head-object --bucket "$BUCKET" --key "$OBJECT_KEY" --version-id "$VERSION_ID" \
  >"$OUT/raw/head-object-after-delete-attempts.json"

cat >"$OUT/activation-summary.json" <<EOF
{
  "providerProfile": "aws-s3-object-lock-compliance",
  "bucket": "$BUCKET",
  "region": "$REGION",
  "objectKey": "$OBJECT_KEY",
  "objectVersionId": "$VERSION_ID",
  "artifactSha256": "$EXPECTED_SHA256",
  "artifactBytes": $EXPECTED_BYTES,
  "retentionDays": $RETENTION_DAYS,
  "status": "raw-evidence-captured-not-yet-attested"
}
EOF
printf 'M0-A12 AWS raw evidence written to %s\n' "$OUT"
