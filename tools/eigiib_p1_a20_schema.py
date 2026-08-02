from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def validate_draft202012_instance(schema: Mapping[str, Any], instance: Any) -> None:
    if not isinstance(schema, Mapping):
        raise TypeError("schema must be an object")
    if schema.get("$schema") != DRAFT_2020_12:
        raise ValueError("schema draft mismatch")
    validator_class = validator_for(schema)
    if validator_class is not Draft202012Validator:
        raise ValueError("schema did not select Draft202012Validator")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(instance)
