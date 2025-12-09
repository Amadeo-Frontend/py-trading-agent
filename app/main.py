from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import health, chat, auth
from .database import Base, engine, SessionLocal
from .core.security import hash_password
from .models import User


def init_admin() -> None:
    """
    Cria o usuário admin no banco se ainda não existir.
    Usa as variáveis de ambiente ADMIN_EMAIL / ADMIN_PASSWORD / ADMIN_NAME.
    """
    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        # se não configurou no .env, não faz nada
        return

    db = SessionLocal()
    try:
        existing = (
            db.query(User)
            .filter(User.email == settings.ADMIN_EMAIL)
            .first()
        )
        if existing:
            return

        admin = User(
            email=settings.ADMIN_EMAIL,
            name=settings.ADMIN_NAME,
            hashed_password=hash_password(settings.ADMIN_PASSWORD),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()


def create_app() -> FastAPI:
    # cria tabelas e garante admin
    Base.metadata.create_all(bind=engine)
    init_admin()

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
