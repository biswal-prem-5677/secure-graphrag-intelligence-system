"""
Database repositories providing persistent CRUD operations with strict server-side multi-user isolation.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.db.models import (
    DBFeedback,
    DBProfile,
    DBSavedInvestigation,
    DBSessionContext,
    DBSubscription,
    DBUser,
    DBUserMemory,
    DBUserUsage,
)


class UserRepository:
    @staticmethod
    def get_by_username(username: str, db: Optional[Session] = None) -> Optional[DBUser]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return db.query(DBUser).filter(DBUser.username == username).first()
        finally:
            if close:
                db.close()

    @staticmethod
    def get_by_id(user_id: str, db: Optional[Session] = None) -> Optional[DBUser]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return db.query(DBUser).filter(DBUser.id == user_id).first()
        finally:
            if close:
                db.close()

    @staticmethod
    def get_by_email(email: str, db: Optional[Session] = None) -> Optional[DBUser]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return db.query(DBUser).filter(DBUser.email == email).first()
        finally:
            if close:
                db.close()

    @staticmethod
    def create(username: str, hashed_password: str, email: Optional[str] = None, role: str = "analyst", db: Optional[Session] = None) -> DBUser:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            user = DBUser(
                id=str(uuid.uuid4()),
                username=username,
                email=email,
                hashed_password=hashed_password,
                role=role,
                disabled=False,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            return user
        finally:
            if close:
                db.close()

    @staticmethod
    def list_all(db: Optional[Session] = None) -> List[DBUser]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return db.query(DBUser).all()
        finally:
            if close:
                db.close()


class ProfileRepository:
    @staticmethod
    def get_or_create(user_id: str, display_name: Optional[str] = None, email: Optional[str] = None, role_title: str = "Security Analyst", db: Optional[Session] = None) -> DBProfile:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            prof = db.query(DBProfile).filter(DBProfile.user_id == user_id).first()
            if not prof:
                prof = DBProfile(
                    user_id=user_id,
                    display_name=display_name or user_id.capitalize(),
                    email=email or f"{user_id}@intelligence.local",
                    team="Cyber Threat Intelligence Team",
                    role_title=role_title,
                    onboarding_completed=False,
                    preferences_json=json.dumps({"concise_answers": False, "include_raw_subgraph": True, "theme": "light", "default_hops": 2}),
                )
                db.add(prof)
                db.commit()
                db.refresh(prof)
            return prof
        finally:
            if close:
                db.close()

    @staticmethod
    def update(profile: DBProfile, db: Optional[Session] = None) -> DBProfile:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            db.merge(profile)
            db.commit()
            return profile
        finally:
            if close:
                db.close()


class MemoryRepository:
    @staticmethod
    def get_memories(user_id: str, db: Optional[Session] = None) -> List[DBUserMemory]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return db.query(DBUserMemory).filter(DBUserMemory.user_id == user_id).order_by(DBUserMemory.created_at.desc()).all()
        finally:
            if close:
                db.close()

    @staticmethod
    def add_or_update(user_id: str, key: str, value: str, category: str = "preference", db: Optional[Session] = None) -> DBUserMemory:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            mem = db.query(DBUserMemory).filter(DBUserMemory.user_id == user_id, DBUserMemory.key == key).first()
            if mem:
                mem.value = value
                mem.category = category
            else:
                mem = DBUserMemory(id=str(uuid.uuid4()), user_id=user_id, key=key, value=value, category=category)
                db.add(mem)
            db.commit()
            db.refresh(mem)
            return mem
        finally:
            if close:
                db.close()

    @staticmethod
    def delete(user_id: str, memory_id: str, db: Optional[Session] = None) -> bool:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            count = db.query(DBUserMemory).filter(DBUserMemory.user_id == user_id, DBUserMemory.id == memory_id).delete()
            db.commit()
            return count > 0
        finally:
            if close:
                db.close()

    @staticmethod
    def clear_all(user_id: str, db: Optional[Session] = None) -> None:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            db.query(DBUserMemory).filter(DBUserMemory.user_id == user_id).delete()
            db.query(DBSessionContext).filter(DBSessionContext.user_id == user_id).delete()
            db.commit()
        finally:
            if close:
                db.close()

    @staticmethod
    def get_session_context(session_id: str, user_id: str, db: Optional[Session] = None) -> DBSessionContext:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            ctx = db.query(DBSessionContext).filter(
                DBSessionContext.session_id == session_id,
                DBSessionContext.user_id == user_id,
            ).first()
            if not ctx:
                ctx_id = f"{user_id}:{session_id}"
                ctx = DBSessionContext(
                    id=ctx_id,
                    session_id=session_id,
                    user_id=user_id,
                    history_json="[]",
                    last_entity=None,
                    last_query=None,
                )
                db.add(ctx)
                db.commit()
                db.refresh(ctx)
            return ctx
        finally:
            if close:
                db.close()

    @staticmethod
    def update_session_context(session_id: str, user_id: str, entity: Optional[str], query: str, db: Optional[Session] = None) -> None:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            ctx = db.query(DBSessionContext).filter(
                DBSessionContext.session_id == session_id,
                DBSessionContext.user_id == user_id,
            ).first()
            if not ctx:
                ctx_id = f"{user_id}:{session_id}"
                ctx = DBSessionContext(
                    id=ctx_id,
                    session_id=session_id,
                    user_id=user_id,
                    history_json="[]",
                )
                db.add(ctx)
            if entity:
                ctx.last_entity = entity
            ctx.last_query = query
            try:
                hist = json.loads(ctx.history_json) if ctx.history_json else []
            except Exception:
                hist = []
            hist.append(query)
            ctx.history_json = json.dumps(hist)
            db.commit()
        finally:
            if close:
                db.close()



class SavedInvestigationRepository:
    @staticmethod
    def create(user_id: str, record_data: Dict[str, Any], db: Optional[Session] = None) -> DBSavedInvestigation:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            inv = DBSavedInvestigation(
                id=str(uuid.uuid4()),
                user_id=user_id,
                query_id=record_data.get("query_id", ""),
                query=record_data.get("query", ""),
                title=record_data.get("title", ""),
                answer=record_data.get("answer", ""),
                confidence=str(record_data.get("confidence", "medium")),
                confidence_explanation=record_data.get("confidence_explanation", ""),
                graph_data_json=json.dumps(record_data.get("graph_data", {})),
                relationship_paths_json=json.dumps(record_data.get("relationship_paths", [])),
                evidence_records_json=json.dumps(record_data.get("evidence_records", [])),
                cited_sources_json=json.dumps(record_data.get("cited_sources", [])),
            )
            db.add(inv)
            db.commit()
            db.refresh(inv)
            return inv
        finally:
            if close:
                db.close()

    @staticmethod
    def list_for_user(user_id: str, db: Optional[Session] = None) -> List[DBSavedInvestigation]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return (
                db.query(DBSavedInvestigation)
                .filter(DBSavedInvestigation.user_id == user_id)
                .order_by(DBSavedInvestigation.saved_at.desc())
                .all()
            )
        finally:
            if close:
                db.close()

    @staticmethod
    def get(user_id: str, inv_id: str, db: Optional[Session] = None) -> Optional[DBSavedInvestigation]:
        """Strict server-side ownership filter (anti-IDOR)."""
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return (
                db.query(DBSavedInvestigation)
                .filter(DBSavedInvestigation.user_id == user_id, DBSavedInvestigation.id == inv_id)
                .first()
            )
        finally:
            if close:
                db.close()

    @staticmethod
    def update_title(user_id: str, inv_id: str, new_title: str, db: Optional[Session] = None) -> Optional[DBSavedInvestigation]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            inv = db.query(DBSavedInvestigation).filter(DBSavedInvestigation.user_id == user_id, DBSavedInvestigation.id == inv_id).first()
            if inv:
                inv.title = new_title
                db.commit()
                db.refresh(inv)
            return inv
        finally:
            if close:
                db.close()

    @staticmethod
    def delete(user_id: str, inv_id: str, db: Optional[Session] = None) -> bool:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            count = (
                db.query(DBSavedInvestigation)
                .filter(DBSavedInvestigation.user_id == user_id, DBSavedInvestigation.id == inv_id)
                .delete()
            )
            db.commit()
            return count > 0
        finally:
            if close:
                db.close()


class UsageRepository:
    @staticmethod
    def get_count(user_id: str, date_str: str, db: Optional[Session] = None) -> int:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            rec = db.query(DBUserUsage).filter(DBUserUsage.user_id == user_id, DBUserUsage.date_str == date_str).first()
            return rec.query_count if rec else 0
        finally:
            if close:
                db.close()

    @staticmethod
    def check_and_increment(user_id: str, date_str: str, limit: int, db: Optional[Session] = None) -> Tuple[bool, int, int]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            rec = db.query(DBUserUsage).filter(DBUserUsage.user_id == user_id, DBUserUsage.date_str == date_str).first()
            if not rec:
                rec = DBUserUsage(id=str(uuid.uuid4()), user_id=user_id, date_str=date_str, query_count=0)
                db.add(rec)
                db.flush()
            if rec.query_count >= limit:
                return False, rec.query_count, limit
            rec.query_count += 1
            db.commit()
            return True, rec.query_count, limit
        finally:
            if close:
                db.close()


class SubscriptionRepository:
    @staticmethod
    def get_or_create(user_id: str, db: Optional[Session] = None) -> DBSubscription:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            sub = db.query(DBSubscription).filter(DBSubscription.user_id == user_id).first()
            if not sub:
                sub = DBSubscription(user_id=user_id, plan_tier="free", status="active")
                db.add(sub)
                db.commit()
                db.refresh(sub)
            return sub
        finally:
            if close:
                db.close()

    @staticmethod
    def update(sub: DBSubscription, db: Optional[Session] = None) -> DBSubscription:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            db.merge(sub)
            db.commit()
            return sub
        finally:
            if close:
                db.close()


class FeedbackRepository:
    @staticmethod
    def create(user_id: str, query_id: str, query: str, rating: int, comment: Optional[str] = None, is_hallucination: bool = False, is_incomplete: bool = False, db: Optional[Session] = None) -> DBFeedback:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            fb = DBFeedback(
                id=str(uuid.uuid4()),
                user_id=user_id,
                query_id=query_id,
                query=query,
                rating=rating,
                comment=comment,
                is_hallucination=is_hallucination,
                is_incomplete=is_incomplete,
            )
            db.add(fb)
            db.commit()
            db.refresh(fb)
            return fb
        finally:
            if close:
                db.close()

    @staticmethod
    def list_all(limit: int = 100, db: Optional[Session] = None) -> List[DBFeedback]:
        close = False
        if db is None:
            db = SessionLocal()
            close = True
        try:
            return db.query(DBFeedback).order_by(DBFeedback.created_at.desc()).limit(limit).all()
        finally:
            if close:
                db.close()
