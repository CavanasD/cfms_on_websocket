import secrets
import time
from typing import Optional

from sqlalchemy import VARCHAR, Boolean, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.handler import Base


def _generate_token() -> str:
    """URL-safe 32-char token (24 bytes of entropy)."""
    return secrets.token_urlsafe(24)


class ShareLink(Base):
    """
    Anonymous, time-limited download link for a single Document.

    A holder of the token can fetch the document's current revision without
    authenticating. Optional caps:
      - expires_at: server clock cutoff (epoch seconds), NULL = never expires
      - max_downloads: stop dispensing the file after N successful downloads,
        NULL = unlimited
      - revoked: hard kill switch, set by creator or sysop
    """

    __tablename__ = "share_links"

    token: Mapped[str] = mapped_column(
        VARCHAR(64), primary_key=True, default=_generate_token
    )

    document_id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_by: Mapped[Optional[str]] = mapped_column(
        VARCHAR(64),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    created_at: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )

    expires_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    max_downloads: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    document = relationship("Document")
