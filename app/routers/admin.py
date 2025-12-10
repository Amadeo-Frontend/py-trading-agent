from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..schemas.admin import AdminUser, AdminStatsResponse, UpdateRoleRequest
from ..core.security import get_current_admin_user

router = APIRouter(prefix="/admin", tags=["admin"])


# -----------------------------------------------------------
#  LIST USERS
# -----------------------------------------------------------
@router.get("/users", response_model=list[AdminUser])
def list_users(
    db: Session = Depends(get_db),
    admin = Depends(get_current_admin_user)
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return users


# -----------------------------------------------------------
#  UPDATE ROLE
# -----------------------------------------------------------
@router.patch("/users/{user_id}/role", response_model=AdminUser)
def update_role(
    user_id: int,
    payload: UpdateRoleRequest,
    db: Session = Depends(get_db),
    admin = Depends(get_current_admin_user)
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(404, "Usuário não encontrado")

    if payload.role not in ["admin", "user"]:
        raise HTTPException(400, "Role inválida")

    user.role = payload.role
    db.commit()
    db.refresh(user)
    return user


# -----------------------------------------------------------
#  APPROVE USER
# -----------------------------------------------------------
@router.patch("/users/{user_id}/approve", response_model=AdminUser)
def approve_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin = Depends(get_current_admin_user)
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(404, "Usuário não encontrado")

    user.is_active = True
    db.commit()
    db.refresh(user)
    return user


# -----------------------------------------------------------
#  DELETE USER
# -----------------------------------------------------------
@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin = Depends(get_current_admin_user)
):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(404, "Usuário não encontrado")

    db.delete(user)
    db.commit()
    return {"message": "Usuário removido com sucesso"}


# -----------------------------------------------------------
#  STATS (OPCIONAL)
# -----------------------------------------------------------
@router.get("/stats", response_model=AdminStatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    admin = Depends(get_current_admin_user)
):
    total_users = db.query(User).count()
    pending_users = db.query(User).filter(User.is_active == False).count()
    total_admins = db.query(User).filter(User.role == "admin").count()

    return AdminStatsResponse(
        total_users=total_users,
        pending_users=pending_users,
        active_users=total_users - pending_users,
        total_admins=total_admins,
        today_signups=0,  # opcional (precisa armazenar logs)
    )
