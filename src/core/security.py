from datetime import datetime, timedelta

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from jose import jwt

from src.core.config import JWT_ALGORITHM, JWT_SECRET_KEY
from src.db.db import redis_active_refresh_token, redis_blocked_access_token

__all__ = (
    "Auth",
    "JWTAccessBearer",
    "JWTRefreshBearer"
)


class Auth:

    @staticmethod
    def hash_password(password: str) -> str:
        return CryptContext(schemes=["bcrypt"], deprecated="auto").hash(password)

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        return CryptContext(schemes=["bcrypt"], deprecated="auto").verify(password, hashed_password)

    @staticmethod
    def encode_access_token(user: dict, jti: str) -> str:
        to_encode = {
            "exp": datetime.utcnow() + timedelta(days=0, minutes=30),
            "iat": datetime.utcnow(),
            "jti": jti,
            "scope": "access_token",
        }
        to_encode.update(user)
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def decode_token(token: str, name: str) -> dict:
        try:
            encoded_jwt = jwt.decode(token, JWT_SECRET_KEY, algorithms=JWT_ALGORITHM)
            if encoded_jwt["scope"] == name:
                return encoded_jwt
            raise HTTPException(status_code=401, detail='Scope for the token is invalid')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token expired')
        except Exception:
            raise HTTPException(status_code=401, detail='Invalid token')

    @staticmethod
    def encode_refresh_token(user: dict, jti: str) -> str:
        to_encode = {
            "exp": datetime.utcnow() + timedelta(days=0, hours=10),
            "iat": datetime.utcnow(),
            "jti": jti,
            "scope": "refresh_token",
            "id": user["id"]
        }
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


class JWTAccessBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTAccessBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTAccessBearer, self).__call__(request)
        exp1 = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid auth token")
        if credentials:
            token = Auth.decode_token(credentials.credentials, name="access_token")
            if token is None:
                raise exp1
            for key in redis_blocked_access_token.scan_iter():
                if key == token["jti"]:
                    raise HTTPException(status_code=401, detail='The user is not logged in')
            return credentials.credentials
        else:
            raise exp1


class JWTRefreshBearer(HTTPBearer):

    def __init__(self, auto_error: bool = True):
        super(JWTRefreshBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTRefreshBearer, self).__call__(request)
        exp = HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid auth token")
        if credentials:
            token = Auth.decode_token(credentials.credentials, name="refresh_token")
            active_refresh_jti = redis_active_refresh_token.lrange(str(token["id"]), 0, -1)
            check = False
            for i in active_refresh_jti:
                if token["jti"] == i:
                    check = True
            if not check:
                raise HTTPException(status_code=401, detail='The user is not logged in')
            if token is None:
                raise exp
            return credentials.credentials
        else:
            raise exp
