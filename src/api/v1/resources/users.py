from fastapi import APIRouter, Depends, HTTPException, status

from src.api.v1.schemas import UserModel, UserUpdateModel
from src.core import JWTAccessBearer
from src.services import UserService, get_user_service

router = APIRouter()


@router.get(
    path="/me",
    response_model=UserModel,
    summary="Просмотр профиля",
    tags=["user"],
    status_code=200
)
async def signup(
        token: str = Depends(JWTAccessBearer()), user_service: UserService = Depends(get_user_service)
) -> UserModel:
    user: dict = user_service.watch_user(token)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return UserModel(**user)


@router.put(
    path="/me",
    response_model=UserUpdateModel,
    summary="Обновить информацию о себе",
    tags=["user"],
    status_code=200
)
async def update(user: dict,
                 token: str = Depends(JWTAccessBearer()), user_service: UserService = Depends(get_user_service)
                 ) -> UserModel:
    result = user_service.update_user(user=user, token=token)
    print(result)
    return UserUpdateModel(**result)
