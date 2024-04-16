# Mocked OIDC

Do not use this in prod! It's intended for testing & spike test purposes only.
Every line of code contains at least one zero day and 900 CVEs.

## User Factory

1) `auth_code_allow = "all"` All requests are accepted (auth code grant is completely mocked)
   and a default user is returned in the JWT
2) `auth_code_allow = "alpha-key"` Authorization code has two parts, separated by a dot:
   - **alpha key:** a pre-generated code found in alphakeys.txt
   - **user claims:** base64 encoded json of user, serves as the body of the JWT
