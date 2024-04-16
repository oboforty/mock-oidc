import uuid

from issuejwt import to_jwt

print("""
Game IDs:
XX - test game
PI - Piratepoly
JI - Japanopoly
DI - Diplomatica
GEO - Geopoly
""")
username = input("Username:")
gid = input("Game ID:")
assert gid and username


aud = f'est:{gid}'
issuer = 'https://est3.pythonanywhere.com/'
token = to_jwt({
    'uid': str(uuid.uuid4()),
    'username': username,
    'gid': gid,
    'scope': 'profile,points,face',
    'points': 99999,
    'face': [],
    'admin': True,
    'sn': True,
}, issuer=issuer, audience=aud, expiry=99999999, type='master')

print("Your master JWT:\n", token)