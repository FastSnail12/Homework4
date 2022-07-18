import redis
import uvicorn
from fastapi import FastAPI

from src.api.v1.resources import posts, users, auth
from src.core import config
from src.db import cache, redis_cache

app = FastAPI(
    title=config.PROJECT_NAME,
    version=config.VERSION,
    docs_url="/api/openapi",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


@app.on_event("startup")
async def startup():
    cache.cache = redis_cache.CacheRedis(
        cache_instance=redis.Redis(
            host=config.REDIS_HOST, port=config.REDIS_PORT, max_connections=10
        )
    )


@app.on_event("shutdown")
async def shutdown():
    cache.cache.close()


app.include_router(router=posts.router, prefix="/api/v1/posts")
app.include_router(router=auth.router, prefix="/api/v1")
app.include_router(router=users.router, prefix="/api/v1/users")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
    )
