from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from caretaker.logging.interrogation import InterrogationRequest, LogInterrogator
from caretaker.logging.models import LogChannel, LogEnvelope


def _record(*, occurred_at: datetime, call_id, incident_id) -> LogEnvelope:
    return LogEnvelope(
        schema_version=1,
        writer_version="0.6.0a1",
        record_id=uuid4(),
        occurred_at=occurred_at,
        monotonic_ns=1,
        process_start_id=uuid4(),
        sequence_number=1,
        channel=LogChannel.GUARD,
        severity=30,
        logger_name="test.guard",
        message_template=None,
        formatted_message=str(incident_id),
        fields={},
        process_id=1,
        thread_id=1,
        task_id=None,
        run_id=uuid4(),
        call_id=call_id,
        target_id="lab.divide",
        function_version=1,
        incident_id=incident_id,
    )


def test_interrogation_filters_selected_call_and_incident_context() -> None:
    now = datetime.now(timezone.utc)
    selected_call, other_call = uuid4(), uuid4()
    selected_incident, other_incident = uuid4(), uuid4()
    selected = _record(
        occurred_at=now,
        call_id=selected_call,
        incident_id=selected_incident,
    )
    other = _record(
        occurred_at=now,
        call_id=other_call,
        incident_id=other_incident,
    )
    request = InterrogationRequest(
        period_start=now - timedelta(minutes=1),
        period_end=now + timedelta(minutes=1),
        target_ids=("lab.divide",),
        call_ids=(selected_call,),
        incident_ids=(selected_incident,),
    )

    bundle = LogInterrogator().build_bundle(request, (other, selected))

    assert bundle.representative_logs == (selected,)
