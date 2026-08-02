from __future__ import annotations
import json,pathlib
from eigiib_p1_a17_common import ROOT,validate_all
for name in ['eigiib-p1-a17-bundle.schema.json','eigiib-p1-a17-route-result.schema.json']:
 p=ROOT/'schemas'/name;v=json.loads(p.read_text());assert v['$schema']=='https://json-schema.org/draft/2020-12/schema';assert v.get('additionalProperties') is False or v['type']=='object'
validate_all();print('P1-A17 closed schemas and fixtures: conformant')
