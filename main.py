from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError

app = FastAPI()

# 1. Define your unique assignment constants
ASSIGNED_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ASSIGNED_ISSUER = "https://idp.exam.local"
ASSIGNED_AUDIENCE = "tds-33649ynk.apps.exam.local"

# 2. Define what the incoming request JSON data looks like
class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
def verify_token(request_data: TokenRequest):
    try:
        # 3. Decode and verify the token. PyJWT checks:
        #    - RS256 signature alignment with the public key
        #    - Exact 'iss' match
        #    - Exact 'aud' match
        #    - 'exp' timestamp expiration check
        payload = jwt.decode(
            request_data.token,
            ASSIGNED_PUBLIC_KEY,
            algorithms=["RS256"],
            audience=ASSIGNED_AUDIENCE,
            issuer=ASSIGNED_ISSUER
        )
        
        # 4. Success: Extract and return the required claims
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud")
        }

    except (ExpiredSignatureError, InvalidTokenError):
        # 5. Failure: Any error (expired, tampered, bad aud/iss) triggers a 401 Unauthorized
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"valid": False}
        )

