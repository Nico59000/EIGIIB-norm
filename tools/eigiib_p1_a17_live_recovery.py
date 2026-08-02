from __future__ import annotations

import json
import os
import time

from eigiib_p1_a17_common import OBJECTS, RELEASE_ID, RELEASE_TAG, need, request, route, sha


def live_recovery_authenticated():
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    status = 0
    body = b''
    for delay in (0, 1, 3):
        if delay:
            time.sleep(delay)
        status, body, _ = request(
            f'https://api.github.com/repos/Nico59000/EIGIIB-norm/releases/tags/{RELEASE_TAG}',
            headers,
        )
        if status == 200:
            break
    need(status == 200, f'release API failed: HTTP {status}')
    release = json.loads(body)
    need(
        release['id'] == RELEASE_ID and not release['draft'] and release['prerelease'],
        'release live state mismatch',
    )
    assets = {asset['name']: asset for asset in release['assets']}
    observed = []
    for name, digest, size, _ in OBJECTS:
        need(name in assets, 'recovery asset missing: ' + name)
        status, data, _ = request(
            assets[name]['browser_download_url'],
            {'Accept': 'application/octet-stream'},
        )
        need(
            status == 200 and len(data) == size and 'sha256:' + sha(data) == digest,
            'recovery live mismatch: ' + name,
        )
        observed.append({'name': name, 'digest': digest, 'size': size})
    return observed


print(
    json.dumps(
        route(
            'reference-python-github-release',
            {'location': 'recovery', 'objects': live_recovery_authenticated()},
        ),
        sort_keys=True,
        separators=(',', ':'),
    )
)
