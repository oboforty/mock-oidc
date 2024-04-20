import base64
import binascii
import json
import random
import string
import sys
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request, url_for

from config import CFG
from cors import Cors
from issuejwt import verify, to_jwt

app = Flask(
  __name__,
  static_url_path='/',
  static_folder='./public'
)
cors = Cors(CFG['cors'])
app.after_request(lambda resp: cors(request, resp))

auth_code_db = dict()
alphakeys_file = CFG.get('alphakeys_file', Path(__file__).parent.joinpath('alphakeys.txt'))


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "resp": "Mocked OIDC Server",
        "auth_codes": auth_code_db,
        "audience": CFG['audience']
    })


if CFG['auth_code_allow'] == 'all':
    @app.route('/oauth/authorize')
    def authorization_endpoint():
        user = CFG['default_user']
        redirect_uri = request.args['redirect_uri']

        url = urlparse(redirect_uri)
        audience = f'{url.scheme}://{url.netloc}/'
        # client_audiences.add(audience)

        auth_code = ''.join(random.choices(string.ascii_letters, k=32))
        auth_code_db[auth_code] = user['uid'], audience

        # CSRF & redirect are skipped
        return f"""<html>
          <body>
           <h1>Fetch authorization token:</h1>
           <p>Hello, {user['username']}</p>
    
           <a href="{redirect_uri}?authorization_code={auth_code}">Click here</a>
    
           <input type="text" onfocus="this.select();" onmouseup="return false;" value="{auth_code}" />
    
          </body>
        </html>"""
else:
    @app.route('/oauth/authorize')
    def authorization_endpoint():
        return f"""<html>
          <body>
            <h1>Access Denied:</h1>
            <p>Auth codes were pre-generated for this server, ask one from the administrator of this server.
            Auth code grant is disabled.</p>
          </body>
        </html>"""


@app.route('/oauth/token', methods=['POST'])
def token_endpoint():
    if request.is_json:
        authorization_code: str = request.json.get('code')
    else:
        authorization_code: str = request.args.get('authorization_code')

    if not authorization_code:
        return jsonify(""), 401

    if CFG['auth_code_allow'] == 'alpha-key-list':
        """
        Read user dict from 2nd part of authorization code
        """
        user_alphakey, user_encoded = authorization_code.split('.')
        is_testing_key = user_alphakey == CFG['testing_alphakey']

        try:
            if not is_testing_key:
                with open(alphakeys_file) as fh:
                    alphakeys = set(fh.readlines())

                alphakeys.remove(user_alphakey+'\n')
            user = json.loads(base64.b64decode(user_encoded.encode('utf8')))
            audience = user.pop('audience', None)
            token_type = 'alpha'

            if not is_testing_key:
                with open(alphakeys_file, 'w') as fh:
                    fh.writelines(alphakeys)
        except (KeyError, binascii.Error, json.JSONDecodeError) as e:
            sys.stderr.write(f'Auth error: {e}\n')
            return jsonify(""), 403

    elif CFG['auth_code_allow'] == 'all':
        """
        Accept authorization code at face value, and fetch user from config
        """
        user = CFG['default_user']
        token_type = 'access'

        try:
            uid, audience = auth_code_db[authorization_code]
            assert uid == user['uid']
        except (KeyError, AssertionError) as e:
            sys.stderr.write(f'Auth error: {e}\n')
            return jsonify(""), 403
    else:
        raise NotImplemented(CFG['auth_code_allow'])

    token = to_jwt(user, issuer=request.url_root, audience=audience, type=token_type)

    return jsonify({
        'access_token': token
    })


@app.route('/oauth/user')
def userinfo_endpoint():
    try:
        auth = request.headers['Authorization']
    except KeyError:
        return "", 401

    if not (user := verify(auth, issuer=request.url_root, audience=CFG['audience'])):
        return "", 403

    return jsonify(user)


@app.route('/.well-known/openid-configuration')
def oidc_config():
    issuer = request.url_root

    return jsonify({
        "authorization_endpoint": url_for('authorization_endpoint',_external=True),
        "claims_supported": [
          "aud", "iss",
          "exp", "iat", "nbf",
          "sub", "scp"
        ],
        "code_challenge_methods_supported": [
          "plain",
          "S256"
        ],
        "grant_types_supported": [
          "authorization_code",
          "refresh_token",
          "urn:ietf:params:oauth:grant-type:device_code",
          "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ],
        "id_token_signing_alg_values_supported": [
          "RS256"
        ],
        "issuer": url_for('index',_external=True),
        "jwks_uri": f"{issuer}.well-known/jwks.json",
        "response_types_supported": [
          "code",
          "token",
          "none"
        ],
        "scopes_supported": [
          "openid",
          "email",
          "profile"
        ],
        "subject_types_supported": [
          "public"
        ],
        "token_endpoint": url_for('token_endpoint',_external=True),
        "token_endpoint_auth_methods_supported": [
          "client_secret_post",
          "client_secret_basic"
        ],
        "userinfo_endpoint": url_for('userinfo_endpoint',_external=True)
    })


if __name__ == "__main__":
    app.run('0.0.0.0', 5000, debug=False)
