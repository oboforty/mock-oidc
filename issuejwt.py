import os
import time
import random

import jwt

__dir__ = os.path.dirname(__file__)

from config import CFG, _discover_keys

JWKS: dict[str, list[jwt.algorithms.RSAAlgorithm, jwt.algorithms.RSAAlgorithm]] = _discover_keys()


def to_jwt(user, *, issuer: str, audience: str, type: str, expiry=None):

    """
    kid - The token must have a header claim that matches the key in the jwks_uri that signed the token.
    iss - Must match the issuer that is configured for the authorizer.
    aud or client_id - Must match one of the audience entries that is configured for the authorizer.
    exp - Must be after the current time in UTC.
    nbf - Must be before the current time in UTC.
    iat - Must be before the current time in UTC.
    scope or scp - The token must include at least one of the scopes in the route's authorizationScopes.
    """
    now = int(time.time())
    # todo: expiry & refresh token

    kid, (key_priv, _) = random.choice(list(JWKS.items()))

    headers = {'alg': CFG['alg'], 'kid': kid}
    payload = {
        'sub': user.pop('uid'),
        'iss': issuer,
        'aud': audience,
        'exp': now + (expiry or CFG['expiry']),
        'iat': now,
        'nbf': now,
        'scp': 'profile',
        **user
    }

    return jwt.encode(payload, key_priv, headers=headers, algorithm=CFG['alg'])


def verify(header, issuer, audience):
    prefix, token = header.split(' ')
    assert prefix.lower() in ('bearer', 'jwt')

    jwt_headers = jwt.get_unverified_header(token)
    kid = jwt_headers['kid']
    assert jwt_headers['alg'] == CFG['alg']

    try:
        signing_key = JWKS[kid][1]
        data = jwt.decode(token, signing_key, algorithms=[CFG['alg']], audience=audience, issuer=issuer)
    except (jwt.exceptions.PyJWTError, KeyError) as e:
        return None

    return data
    # return json.loads(base64.b64decode(token.split('.')[1].encode('utf8')).decode('utf8'))
