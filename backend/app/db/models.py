"""
SQLAlchemy ORM models for production multi-user persistence.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class DBUser(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), default="analyst", nullable=False)
    disabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    profile = relationship("DBProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    memories = relationship("DBUserMemory", back_populates="user", cascade="all, delete-orphan")
    saved_investigations = relationship("DBSavedInvestigation", back_populates="user", cascade="all, delete-orphan")
    subscription = relationship("DBSubscription", back_populates="user", uselist=False, cascade="all, delete-orphan")


class DBProfile(Base):
    __tablename__ = "profiles"

    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    display_name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=True)
    team = Column(String(100), default="Cyber Threat Intelligence Team", nullable=False)
    role_title = Column(String(100), default="Security Analyst", nullable=False)
    onboarding_completed = Column(Boolean, default=False, nullable=False)
    preferences_json = Column(Text, default="{}", nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    user = relationship("DBUser", back_populates="profile")


class DBUserMemory(Base):
    __tablename__ = "user_memories"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    key = Column(String(100), nullable=False)
    value = Column(Text, nullable=False)
    category = Column(String(50), default="preference", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("DBUser", back_populates="memories")

    __table_args__ = (
        UniqueConstraint("user_id", "key", name="uq_user_memory_key"),
    )


class DBSessionContext(Base):
    __tablename__ = "session_contexts"

    id = Column(String(150), primary_key=True)
    session_id = Column(String(100), nullable=False, index=True)
    user_id = Column(String(100), nullable=False, index=True)
    last_entity = Column(String(255), nullable=True)
    last_query = Column(Text, nullable=True)
    history_json = Column(Text, default="[]", nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("user_id", "session_id", name="uq_session_user"),
    )


class DBSavedInvestigation(Base):
    __tablename__ = "saved_investigations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    query_id = Column(String(100), nullable=False)
    query = Column(Text, nullable=False)
    title = Column(String(255), nullable=False)
    answer = Column(Text, nullable=False)
    confidence = Column(String(32), nullable=False)
    confidence_explanation = Column(Text, nullable=False)
    graph_data_json = Column(Text, default="{}", nullable=False)
    relationship_paths_json = Column(Text, default="[]", nullable=False)
    evidence_records_json = Column(Text, default="[]", nullable=False)
    cited_sources_json = Column(Text, default="[]", nullable=False)
    saved_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    user = relationship("DBUser", back_populates="saved_investigations")


class DBUserUsage(Base):
    __tablename__ = "user_usage"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    date_str = Column(String(10), nullable=False, index=True)
    query_count = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        UniqueConstraint("user_id", "date_str", name="uq_user_usage_date"),
    )


class DBSubscription(Base):
    __tablename__ = "subscriptions"

    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    plan_tier = Column(String(32), default="free", nullable=False)
    status = Column(String(32), default="active", nullable=False)
    stripe_customer_id = Column(String(100), nullable=True, index=True)
    stripe_subscription_id = Column(String(100), nullable=True, index=True)
    current_period_end = Column(DateTime, nullable=True)
    cancel_at_period_end = Column(Boolean, default=False, nullable=False)

    user = relationship("DBUser", back_populates="subscription")


class DBFeedback(Base):
    __tablename__ = "feedbacks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    query_id = Column(String(100), nullable=False)
    query = Column(Text, nullable=False)
    rating = Column(Integer, nullable=False)
    comment = Column(Text, nullable=True)
    is_hallucination = Column(Boolean, default=False, nullable=False)
    is_incomplete = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
