from __future__ import annotations
import argparse,json,pathlib
from eigiib_p1_a17_common import canonical,report
p=argparse.ArgumentParser();p.add_argument('--output');a=p.parse_args();data=canonical(report())
if a.output:pathlib.Path(a.output).write_bytes(data)
print(data.decode(),end='')
