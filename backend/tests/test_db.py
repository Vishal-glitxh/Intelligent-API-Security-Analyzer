import uuid

from app.db.models import AuditEvent
from app.db.session import SessionLocal, get_db
from sqlalchemy import select


def test_get_db_yields_session() -> None:
    generator = get_db()
    session = next(generator)
    try:
        assert session is not None
        assert session.is_active
    finally:
        try:
            next(generator)
        except StopIteration:
            pass


def test_audit_event_persistence() -> None:
    test_action = f"test_action_{uuid.uuid4().hex[:8]}"
    with SessionLocal() as session:
        event = AuditEvent(
            action=test_action,
            actor="test-runner",
            target_type="scan",
            target_id="scan-001",
            details="Phase 1 test audit event",
        )
        session.add(event)
        session.commit()
        session.refresh(event)

        assert event.id is not None
        assert event.action == test_action
        assert event.created_at is not None

        # Query back
        stmt = select(AuditEvent).where(AuditEvent.action == test_action)
        retrieved = session.scalars(stmt).first()
        assert retrieved is not None
        assert retrieved.actor == "test-runner"

        # Cleanup
        session.delete(retrieved)
        session.commit()
