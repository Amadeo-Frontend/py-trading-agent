from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings
from app.models import User
from app.database import SessionLocal

# ------------------------------
# CONFIG JWT
# ------------------------------

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ------------------------------
# PASSWORD FUNCTIONS
# ------------------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ------------------------------
# TOKEN
# ------------------------------

def create_access_token(user_id: int, role: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire,
    }

    encoded = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded


# ------------------------------
# CURRENT USER HELPERS
# ------------------------------

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Valida JWT e retorna o usuário logado"""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")

        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    db = SessionLocal()
    user = db.query(User).filter(User.id == int(user_id)).first()
    db.close()

    if not user or not user.is_active:
        raise credentials_exception

    return user


def get_current_admin_user(current_user: User = Depends(get_current_user)):
    """Permite acesso apenas para admin"""

    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins only",
        )

    return current_user
