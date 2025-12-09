from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import health, chat, auth
from .database import Base, engine

def create_app() -> FastAPI:
    # cria as tabelas (para algo mais sério, depois usamos Alembic)
    Base.metadata.create_all(bind=engine)

    app = FastAPI(title="Trading Agent Backend")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.frontend_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(chat.router)

    return app

app = create_app()
