from sqlalchemy.orm import Session

from pcapvis.db.models import AuditEvent, User


def record(
    db: Session,
    user: User | None,
    action: str,
    *,
    engagement_id: int | None = None,
    target: str = "",
    details: dict | None = None,
) -> None:
    """Add an audit event to the session (committed with the caller's change)."""
    db.add(
        AuditEvent(
            user_id=user.id if user else None,
            engagement_id=engagement_id,
            action=action,
            target=target[:255],
            details=details,
        )
    )
