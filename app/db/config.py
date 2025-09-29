from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from fastapi import Depends
from typing import AsyncGenerator, Annotated
from decouple import config


DB_USER = config("DB_USER")
DB_PASS = config("DB_PASS")
DB_NAME = config("DB_NAME")
DB_PORT = config("DB_PORT", cast = int)
DB_HOST = config("DP_HOST")
DATABASEURL = f"mysql+aiomysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
 
engine = create_async_engine(DATABASEURL, echo=True, future=True)

async_session = async_sessionmaker(bind=engine, expire_on_commit=False, class_= AsyncSession)

async def get_session() -> AsyncGenerator[AsyncSession,None]:
    async with async_session() as session:
        yield session

SessionDep = Annotated[AsyncSession,Depends(get_session)]