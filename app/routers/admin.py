from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from ..database import get_db
from ..models import User
from ..core.security import get_current_admin_user

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats")
def admin_stats(db: Session = Depends(get_db), admin=Depends(get_current_admin_user)):
    total_users = db.query(User).count()

    pending_users = db.query(User).filter(User.is_active == False).count()

    active_users = db.query(User).filter(User.is_active == True).count()

    total_admins = db.query(User).filter(User.role == "admin").count()

    # usuários criados hoje
    today = datetime.utcnow().date()
    today_signups = (
        db.query(User)
        .filter(User.created_at >= datetime(today.year, today.month, today.day))
        .count()
    )

    # últimos 10 cadastrados
    latest_users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .limit(10)
        .all()
    )

    return {
        "total_users": total_users,
        "pending_users": pending_users,
        "active_users": active_users,
        "total_admins": total_admins,
        "today_signups": today_signups,
        "latest_users": [
            {
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "created_at": u.created_at.isoformat(),
                "role": u.role,
                "is_active": u.is_active,
            }
            for u in latest_users
        ],
    }
