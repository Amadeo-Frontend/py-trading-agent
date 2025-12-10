# app/routers/admin.py
from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..core.security import get_current_admin_user
from ..database import get_db
from ..models import LoginEvent, User
from ..schemas.admin import AdminDailyLogin, AdminStats, AdminUser

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------- Helpers ----------


def _to_admin_user(db: Session, user: User) -> AdminUser:
    last_login = (
        db.query(func.max(LoginEvent.created_at))
        .filter(LoginEvent.user_id == user.id)
        .scalar()
    )

    return AdminUser(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=last_login,
    )


# ---------- Endpoints ----------


@router.get("/users", response_model=List[AdminUser])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin_user),
    search: str | None = Query(None, description="filtrar por email ou nome"),
):
    query = db.query(User)

    if search:
        like = f"%{search}%"
        query = query.filter(
            func.lower(User.email).like(func.lower(like))
            | func.lower(User.name).like(func.lower(like))
        )

    query = query.order_by(User.created_at.desc())

    users = query.all()
    return [_to_admin_user(db, u) for u in users]


@router.patch("/users/{user_id}/role", response_model=AdminUser)
def update_user_role(
    user_id: int,
    role: str,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin_user),
):
    if role not in ("admin", "user"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role inválida",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user.role = role
    db.commit()
    db.refresh(user)
    return _to_admin_user(db, user)


@router.patch("/users/{user_id}/approve", response_model=AdminUser)
def approve_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin_user),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user.is_active = True
    db.commit()
    db.refresh(user)
    return _to_admin_user(db, user)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin_user),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    db.delete(user)
    db.commit()
    return


@router.get("/stats", response_model=AdminStats)
def get_stats(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_admin_user),
):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    total_users = db.query(func.count(User.id)).scalar() or 0
    active_users = (
        db.query(func.count(User.id)).filter(User.is_active.is_(True)).scalar() or 0
    )
    admins = (
        db.query(func.count(User.id)).filter(User.role == "admin").scalar() or 0
    )
    pending_users = (
        db.query(func.count(User.id)).filter(User.is_active.is_(False)).scalar() or 0
    )

    logins_last_24h = (
        db.query(func.count(LoginEvent.id))
        .filter(LoginEvent.created_at >= last_24h)
        .scalar()
        or 0
    )

    # logins por dia (últimos 7 dias)
    day_col = func.date(LoginEvent.created_at)
    rows = (
        db.query(day_col.label("day"), func.count(LoginEvent.id))
        .group_by("day")
        .order_by("day")
        .limit(7)
        .all()
    )
    logins_per_day = [
        AdminDailyLogin(day=row.day, count=row[1]) for row in rows
    ]

    # últimos usuários criados
    last_users_db = (
        db.query(User)
        .order_by(User.created_at.desc())
        .limit(5)
        .all()
    )
    last_users = [_to_admin_user(db, u) for u in last_users_db]

    return AdminStats(
        total_users=total_users,
        active_users=active_users,
        admins=admins,
        pending_users=pending_users,
        logins_last_24h=logins_last_24h,
        logins_per_day=logins_per_day,
        last_users=last_users,
    )
