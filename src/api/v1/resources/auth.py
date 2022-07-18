from http import HTTPStatus
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from src.api.v1.schemas import UserSignup, UserLogin, UserModel, UserJwtToken
from src.services import UserService, get_user_service
from src.core import JWTAccessBearer, JWTRefreshBearer

router = APIRouter()


@router.post(
    path="/signup",
    response_model=UserModel,
    summary="Создать аккаунт",
    tags=["auth"],
    status_code=201
)
async def signup(
        user: UserSignup, user_service: UserService = Depends(get_user_service),
) -> UserModel:
    if user_service.is_username_first(user.username):
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="A user with this username already exists")
    user: dict = user_service.singup(user=user)
    return UserModel(**user)


@router.post(
    path="/login",
    response_model=UserJwtToken,
    summary="Войти в аккаунт",
    tags=["auth"],
    status_code=200
)
async def login(
        user: UserLogin, user_service: UserService = Depends(get_user_service)
) -> UserJwtToken:
    tokens: Optional[dict] = user_service.login(user=user)
    if tokens:
        return UserJwtToken(**tokens)
    raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="Invalid username or password")


@router.post(
    path="/refresh",
    response_model=UserJwtToken,
    summary="Обновить токен",
    tags=["auth"],
    status_code=200
)
async def refresh_token(
        token: str = Depends(JWTRefreshBearer()), user_service: UserService = Depends(get_user_service)
) -> UserJwtToken:
    access_token: str = user_service.refresh(token)
    return UserJwtToken(**{"access_token": access_token, "refresh_token": token})


@router.post(
    path="/logout",
    summary="Выход из аккаунта",
    tags=["auth"],
    status_code=200
)
async def logout(
        access_token: str = Depends(JWTAccessBearer()), user_service: UserService = Depends(get_user_service)
) -> dict:
    user_service.logout(access_token)
    return {"msg": "You have been logged out."}


@router.post(
    path="/logout_all",
    summary="Выйти со всех устройств",
    tags=["auth"],
    status_code=200
)
async def logout_all(
        access_token: str = Depends(JWTAccessBearer()), user_service: UserService = Depends(get_user_service)
) -> dict:
    user_service.logout_all(access_token)
    return {"msg": "You have been logged out from all devices."}
