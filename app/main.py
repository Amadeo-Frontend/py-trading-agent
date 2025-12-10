from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .routers import health, chat, auth, admin
from .database import Base, engine, SessionLocal
from .core.security import hash_password
from .models import User


def init_admin() -> None:
    """
    Cria o usuário admin no banco se ainda não existir.
    Usa as variáveis ADMIN_EMAIL, ADMIN_PASSWORD e ADMIN_NAME do .env.
    """
    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        print("⚠️ ADMIN_EMAIL e ADMIN_PASSWORD não configurados — admin não será criado.")
        return

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if existing:
            print("✔️ Admin já existe — ignorando seed.")
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
        print("🎉 Admin criado com sucesso no banco!")

    finally:
        db.close()


def create_app() -> FastAPI:
    # Criar tabelas e ativar seed de admin
    Base.metadata.create_all(bind=engine)
    init_admin()

    app = FastAPI(title="Trading Agent Backend")

    # CORS para Next.js
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.frontend_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Registrando rotas
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(chat.router)
    app.include_router(admin.router)

    return app


app = create_app()
