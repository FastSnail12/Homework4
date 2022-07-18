from sqlmodel import Session, create_engine
from redis import Redis

from src.core.config import DATABASE_URL, REDIS_HOST, REDIS_PORT

__all__ = (
    "get_session",
    "redis_active_refresh_token",
    "redis_blocked_access_token",
)

engine = create_engine(DATABASE_URL, echo=True)
redis_blocked_access_token = Redis(host=REDIS_HOST, port=REDIS_PORT, db=1, decode_responses=True)
redis_active_refresh_token = Redis(host=REDIS_HOST, port=REDIS_PORT, db=2, decode_responses=True)


async def get_session():
    with Session(engine) as session:
        yield session
