from __future__ import annotations

from eigiib_p1_a19_common import FIXTURE, load_json, validate_bundle

schema = load_json(FIXTURE.parent.parent.parent / "schemas/eigiib-p1-a19-bundle.schema.json")
bundle = load_json(FIXTURE / "interoperability-bundle.json")
if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
    raise SystemExit("schema draft mismatch")
if schema.get("additionalProperties") is not False:
    raise SystemExit("bundle schema is not closed")
validate_bundle(bundle)
print("P1-A19 closed schema and semantic validation: PASS")
