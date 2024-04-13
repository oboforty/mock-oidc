from collections import defaultdict
import json
from pathlib import Path

import jwt

base = Path(__file__).parent

with open(f'{base}/config.json') as fh:
    CFG = json.load(fh)


def _discover_keys():
    with open(base.joinpath('jwks_private.json')) as fh:
        jwks_prv = json.load(fh)['keys']
    with open(base.joinpath('public', '.well-known', 'jwks.json')) as fh:
        jwks_pub = json.load(fh)['keys']

    jwks = defaultdict(lambda: [None, None])

    for jwk_prv in jwks_prv:
        jwks[jwk_prv['kid']][0] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk_prv))
    for jwk_pub in jwks_pub:
        jwks[jwk_pub['kid']][1] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk_pub))
    return dict(jwks)
