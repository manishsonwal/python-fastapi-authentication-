from fastapi import FastAPI
from app.accounts.routers import router as acoount_router

app = FastAPI(title = "Fastapi auth")

@app.get("/")
def root():
    return {"massages" "fastapi app"}

app.include_router(acoount_router, prefix="/api/account", tags=["Account"])


