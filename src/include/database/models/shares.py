from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING

from sqlalchemy import VARCHAR, Boolean, Double, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base

if TYPE_CHECKING:
    from include.database.models.documents import Document
    from include.database.models.identity import User


class ShareLink(Base):
    __tablename__ = "share_links"

    token: Mapped[str] = mapped_column(
        VARCHAR(64), primary_key=True, default=lambda: secrets.token_urlsafe(24)
    )
    document_id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[str | None] = mapped_column(
        VARCHAR(64),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[float] = mapped_column(
        Double, nullable=False, default=lambda: time.time()
    )
    expires_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    max_downloads: Mapped[int | None] = mapped_column(Integer, nullable=True)
    download_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    document: Mapped[Document] = relationship("Document")
    creator: Mapped[User | None] = relationship("User", foreign_keys=[created_by])
