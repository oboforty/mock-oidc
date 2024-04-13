import random
import string
from urllib.parse import urlparse

from flask import Flask, jsonify, request, url_for

from config import CFG
from issuejwt import verify, to_jwt

app = Flask(
  __name__,
  static_url_path='/',
  static_folder='./public'
)

auth_code_db = dict()
client_audiences = set()


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "resp": "Mocked OIDC Server",
        "auth_codes": auth_code_db,
        "issued_audiences": list(client_audiences)
    })


@app.route('/oauth/authorize')
def authorization_endpoint():
    user = CFG['user']
    redirect_uri = request.args['redirect_uri']

    url = urlparse(redirect_uri)
    audience = f'{url.scheme}://{url.netloc}/'
    client_audiences.add(audience)

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


@app.route('/oauth/token', methods=['POST'])
def token_endpoint():
    user = CFG['user']

    try:
        authorization_code = request.args['authorization_code']
        uid, client_uri = auth_code_db[authorization_code]
        assert uid == user['uid']
    except (KeyError, AssertionError):
        return jsonify(""), 403

    token = to_jwt(user, issuer=request.url_root, audience=client_uri)
    return jsonify({
      'access_token': token
    })


@app.route('/oauth/user')
def userinfo_endpoint():
    try:
        auth = request.headers['Authorization']
    except KeyError:
        return "", 401

    if not (user := verify(auth, issuer=request.url_root, audience=list(client_audiences))):
        return "", 403

    return jsonify(user)


@app.route('/.well-known/openid-configuration')
def oidc_config():
    issuer = request.url_root

    return jsonify({
        "authorization_endpoint": url_for('authorization_endpoint',_external=True),
        "claims_supported": list(CFG['user'].keys()) + [
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
