from __future__ import annotations

from datetime import datetime, timedelta, timezone

from caretaker.logging import (
    BaselineBuilder,
    BaselineComparator,
    BaselineKey,
    LoggingRuntime,
    MaskingResult,
    OperatorLoggingPolicy,
    logged,
    read_segment,
)
from caretaker.logging.handler import _default_runtime
import caretaker.logging.handler as handler_module


def test_logged_decorator_masks_before_persistence(tmp_path):
    runtime = LoggingRuntime(
        OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="demo"),
        supervised=True,
    )
    handler_module._default_runtime = runtime

    def masker(args, kwargs):
        return MaskingResult(
            masked_args=("XXXX-XXXX-XXXX-1234", args[1]),
            masked_kwargs=kwargs,
            structural_metadata={"card_length": 16},
            format_preserved_fields=("card_number",),
        )

    @logged(arguments=True, mask=masker, baseline_dimensions=("card_number",))
    def charge(card_number, amount):
        return amount * 2

    assert charge("4111111111111234", 10) == 20
    manifest = runtime.close()
    segments = list((tmp_path / "application" / "events").glob("*.ctlog"))
    records = tuple(item for path in segments for item in read_segment(path))
    text = repr(records)
    assert "4111111111111234" not in text
    assert "XXXX-XXXX-XXXX-1234" in text
    handler_module._default_runtime = None


def test_baselines_compare_absolute_relative_and_per_unit_growth(tmp_path):
    runtime = LoggingRuntime(
        OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="demo"),
        supervised=True,
    )
    handler_module._default_runtime = runtime

    @logged(timing=True, baseline_dimensions=("kind",))
    def work(kind):
        return kind

    for _ in range(4):
        work("a")
    runtime.close()
    records = tuple(item for path in (tmp_path / "application" / "events").glob("*.ctlog") for item in read_segment(path))
    start = min(item.occurred_at for item in records)
    end = max(item.occurred_at for item in records)
    builder = BaselineBuilder()
    older = builder.build(records, key=BaselineKey("demo", "1", "test", None, None, None, None), period_start=start, period_end=end)
    newer = builder.build(records + records, key=BaselineKey("demo", "1", "test", None, None, None, None), period_start=start, period_end=end + timedelta(days=30))
    comparison = BaselineComparator().compare(older, newer, units_of_work_old=4, units_of_work_new=8)
    call_changes = [item for item in comparison.significant_changes if item.subject.endswith("call_count")]
    assert call_changes
    assert call_changes[0].relative_change == 1.0
    assert call_changes[0].per_unit_change == 0.0
    handler_module._default_runtime = None


def test_baseline_store_round_trip_and_accept(tmp_path):
    from caretaker.logging import BaselineStore
    from caretaker.logging.models import BaselineKey, BaselineState
    from datetime import datetime, timezone

    baseline = BaselineBuilder().build(
        (),
        key=BaselineKey("app", "1", "test", None, None, None, None),
        period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 2, 1, tzinfo=timezone.utc),
    )
    store = BaselineStore(tmp_path)
    store.save(baseline)
    loaded = store.load(baseline.baseline_id)
    assert loaded.content_hash == baseline.content_hash
    accepted = store.accept(baseline.baseline_id)
    assert accepted.state is BaselineState.ACCEPTED
    assert store.list(state=BaselineState.ACCEPTED)[0].baseline_id == baseline.baseline_id
