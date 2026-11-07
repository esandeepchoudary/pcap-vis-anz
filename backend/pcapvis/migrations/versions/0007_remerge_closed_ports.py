"""re-merge captures: refused connections become "Closed port" links

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-07 07:30:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Links are rebuilt from stored results on the next merge (idempotent; edits are kept).
    op.execute("UPDATE captures SET assets_merged_at = NULL")


def downgrade() -> None:
    pass
