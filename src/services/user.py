import datetime
from typing import Optional
from functools import lru_cache

from fastapi import Depends, HTTPException
from sqlmodel import Session
from uuid import uuid4

from src.api.v1.schemas import UserSignup, UserLogin, UserModel
from src.db import AbstractCache, get_cache, get_session, redis_active_refresh_token, redis_blocked_access_token
from src.models import User
from src.services import ServiceMixin
from src.core.security import Auth

from jose import jwt

from src.core.config import JWT_ALGORITHM, JWT_SECRET_KEY

__all__ = ("UserService", "get_user_service")


class UserService(ServiceMixin):

    def is_username_first(self, username: str) -> bool:
        user = self.session.query(User).filter(User.username == username).first()
        if user:
            return True
        return False

    def singup(self, user: UserSignup) -> dict:
        new_user = User(username=user.username, hashed_password=Auth.hash_password(user.password), email=user.email)
        self.session.add(new_user)
        self.session.commit()
        self.session.refresh(new_user)
        return new_user.dict()

    def login(self, user: UserLogin) -> Optional[dict]:
        user_bd = self.session.query(User).filter(User.username == user.username).first()
        if user_bd:
            user_login = user_bd.dict()
            if Auth.verify_password(user.password, user_login["hashed_password"]):
                del user_login["hashed_password"]
                user_login["created_at"] = str(user_login["created_at"])
                user_login["updated_at"] = str(user_login["updated_at"])
                jti = str(uuid4())
                redis_active_refresh_token.lpush(str(user_login["id"]), jti)
                access_token: str = Auth.encode_access_token(user_login, jti=jti)
                refresh_token: str = Auth.encode_refresh_token(user_login, jti=jti)
                return {"access_token": access_token, "refresh_token": refresh_token}
            return None
        return None

    def refresh(self, refresh_token: str) -> str:
        try:
            encoded_jwt_refresh = jwt.decode(refresh_token, JWT_SECRET_KEY, algorithms=JWT_ALGORITHM)
            active_refresh_jti = redis_active_refresh_token.lrange(str(encoded_jwt_refresh["id"]), 0, -1)
            for i in active_refresh_jti:
                if encoded_jwt_refresh["jti"] == i:

                    if encoded_jwt_refresh["scope"] == "refresh_token":
                        print('ok')
                        user = self.session.query(User).filter(
                            User.id == encoded_jwt_refresh["id"]).first().dict()
                        del user["hashed_password"]
                        user["created_at"] = str(user["created_at"])
                        user["updated_at"] = str(user["updated_at"])
                        new_access_token = Auth.encode_access_token(user, encoded_jwt_refresh["jti"])
                        return new_access_token
                    raise HTTPException(status_code=401, detail='Invalid scope for token')
            raise HTTPException(status_code=401, detail='The user is not logged in')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Refresh token expired')
        except Exception:
            raise HTTPException(status_code=401, detail='Invalid refresh token')

    def update_user(self, token: str, user: dict):
        oldest_user = Auth.decode_token(token, name="access_token")
        user_update = user | {"updated_at": str(datetime.datetime.utcnow())}
        if "password" in user_update:
            user_update["hashed_password"] = Auth.hash_password(user_update["password"])
            del user_update["password"]
        print(user_update)
        self.session.query(User).filter(User.id == oldest_user["id"]).update(user_update,
                                                                             synchronize_session="fetch")
        self.session.commit()
        user_update = self.session.query(User).filter(User.id == oldest_user["id"]).first().dict()
        del user_update["hashed_password"]
        user_update["created_at"] = str(user_update["created_at"])
        user_update["updated_at"] = str(user_update["updated_at"])
        jti = oldest_user["jti"]
        access_token: str = Auth.encode_access_token(user_update, jti=jti)
        return {"user": UserModel(**user_update), "access_token": access_token}

    def watch_user(self, token: str) -> Optional[dict]:
        user = Auth.decode_token(token, name="access_token")
        user = self.session.query(User).filter(User.username == user["username"]).first()
        return user.dict() if user else None

    @staticmethod
    def logout(access_token: str):
        decode_token = Auth.decode_token(access_token, name="access_token")
        jti = decode_token["jti"]
        print(type(jti))
        id_user = decode_token["id"]
        redis_blocked_access_token.set(jti, "")
        active_refresh_jti = redis_active_refresh_token.lrange(str(id_user), 0, -1)
        print(active_refresh_jti)
        count = 0
        for i in active_refresh_jti:
            print(type(i))
            if jti == i:
                print("Hello")
                redis_active_refresh_token.lset(str(id_user), count, "")
                break
            count += 1

    @staticmethod
    def logout_all(access_token: str):
        decode_token = Auth.decode_token(access_token, name="access_token")
        jti = decode_token["jti"]
        id_user = decode_token["id"]
        redis_blocked_access_token.set(jti, "")
        redis_active_refresh_token.delete(str(id_user))


# get_post_service — это провайдер PostService. Синглтон
@lru_cache()
def get_user_service(
        cache: AbstractCache = Depends(get_cache),
        session: Session = Depends(get_session),
) -> UserService:
    return UserService(cache=cache, session=session)
