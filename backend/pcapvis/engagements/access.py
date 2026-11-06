"""Who may do what in an engagement."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from pcapvis.db.models import MAX_MEMBER_ROLE, Engagement, EngagementMember, MemberRole, Role, User


def member_role(db: Session, user: User, engagement: Engagement) -> MemberRole | None:
    """The user's effective role in this engagement, or None if they can't see it at all."""
    if user.role == Role.admin:
        return MemberRole.lead
    m = db.get(EngagementMember, (engagement.id, user.id))
    if m is None:
        return None
    # A global demotion caps existing memberships immediately.
    cap = MAX_MEMBER_ROLE[user.role]
    return m.role if cap.at_least(m.role) else cap


def can_create_engagement(user: User) -> bool:
    return user.role in (Role.admin, Role.lead)


def can_quicklook(user: User) -> bool:
    return user.role != Role.viewer


def visible_engagements(db: Session, user: User):
    """SQL for the engagements this user can see (admins: all)."""
    q = select(Engagement)
    if user.role != Role.admin:
        q = q.join(EngagementMember, EngagementMember.engagement_id == Engagement.id).where(
            EngagementMember.user_id == user.id
        )
    return q
