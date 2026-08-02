from __future__ import annotations
import argparse, pathlib
from eigiib_p1_a18_common import canonical_line, report, validate_bundle
p=argparse.ArgumentParser(); p.add_argument('--output'); p.add_argument('--path',choices=['all','normal','emergency'],default='all'); a=p.parse_args()
v=validate_bundle()
if a.path=='normal': result={'path':'normal','promotionId':v['normalPromotion']['promotionId'],'result':'accepted'}
elif a.path=='emergency': result={'path':'emergency','promotionId':v['emergencyPromotion']['promotionId'],'reviewId':v['review']['reviewId'],'result':'accepted-and-reviewed'}
else: result=report()
data=canonical_line(result)
if a.output: pathlib.Path(a.output).write_bytes(data)
print(data.decode(),end='')
