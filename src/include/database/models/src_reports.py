from __future__ import annotations

import secrets
import time
from typing import TYPE_CHECKING

from sqlalchemy import VARCHAR, BigInteger, Float, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base

if TYPE_CHECKING:
    from include.database.models.documents import Document
    from include.database.models.identity import User


class SrcReport(Base):
    __tablename__ = "src_reports"

    id: Mapped[str] = mapped_column(
        VARCHAR(64), primary_key=True, default=lambda: secrets.token_hex(16)
    )
    reporter_username: Mapped[str] = mapped_column(
        VARCHAR(64),
        ForeignKey("users.username", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(VARCHAR(160), nullable=False)
    category: Mapped[str] = mapped_column(VARCHAR(64), nullable=False)
    severity: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    affected_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    description_md: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        VARCHAR(16), nullable=False, default="pending", server_default="pending"
    )
    created_at: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time(), index=True
    )
    updated_at: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time(), index=True
    )

    reporter: Mapped[User] = relationship("User", foreign_keys=[reporter_username])
    attachments: Mapped[list[SrcReportAttachment]] = relationship(
        "SrcReportAttachment",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="SrcReportAttachment.id",
    )
    events: Mapped[list[SrcReportEvent]] = relationship(
        "SrcReportEvent",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="SrcReportEvent.created_at",
    )


class SrcReportAttachment(Base):
    __tablename__ = "src_report_attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        VARCHAR(64),
        ForeignKey("src_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    document_id: Mapped[str | None] = mapped_column(
        VARCHAR(255),
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )
    filename: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    content_type: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, default="application/octet-stream"
    )
    created_at: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )

    report: Mapped[SrcReport] = relationship(
        "SrcReport", back_populates="attachments"
    )
    document: Mapped[Document | None] = relationship("Document")


class SrcReportEvent(Base):
    __tablename__ = "src_report_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(
        VARCHAR(64),
        ForeignKey("src_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    actor_username: Mapped[str | None] = mapped_column(
        VARCHAR(64),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
    )
    from_status: Mapped[str | None] = mapped_column(VARCHAR(16), nullable=True)
    to_status: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    note_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time(), index=True
    )

    report: Mapped[SrcReport] = relationship("SrcReport", back_populates="events")
    actor: Mapped[User | None] = relationship("User", foreign_keys=[actor_username])
