from __future__ import annotations
import json
from eigiib_p1_a18_common import FIX, exact_keys, load, validate_bundle
schema=load(__import__('pathlib').Path(__file__).resolve().parents[1]/'schemas/eigiib-p1-a18-bundle.schema.json')
exact_keys(schema,{'$schema','$id','title','type','additionalProperties','required','properties','$defs'},'schema')
assert schema['additionalProperties'] is False
for name,definition in schema['$defs'].items():
    if definition.get('type')=='object': assert definition.get('additionalProperties') is False, name
validate_bundle(load(FIX/'governance-bundle.json'))
print(json.dumps({'standard':'EIGIIB-P1-A18-SCHEMA-CHECK-1.0','result':'conformant'},sort_keys=True,separators=(',',':')))
