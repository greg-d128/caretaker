# Caretaker monitoring stream

Caretaker can optionally publish a small, output-only metric stream for an
external collector. It is disabled by default, so the least-friction policy
does not create another file or require a monitoring system. The stream is
telemetry only: Caretaker never reads it as a command, policy, approval, or
authority source.

## Policy

Enable it in the operator policy when a local collector is available:

```toml
[logging.monitoring]
enabled = true
file_name = "caretaker_monitoring.log"
dialect = "json_lines"
maximum_record_bytes = 4096

[logging.metrics]
enabled = true
provider_name = "process"
sample_interval_seconds = 5.0
maximum_samples_per_snapshot = 64
correlate_by_process = true
correlate_by_call = false
correlate_by_target = true
correlate_by_incident = true
correlate_by_guard_window = true
correlate_by_baseline = true
```

The file name must remain below `logging.directory`. Configuration is
startup-bound and the writer uses mode `0600` when the platform permits it.
Records accept finite numeric values, at most 32 bounded dimensions, and a
bounded metric name. Oversized or malformed records are rejected before they
are written.

## Common record

The canonical record has this shape in `JSON_LINES` mode:

```json
{"application_id":"payments","dimensions":{"region":"us-east"},"metric":"caretaker.logging.queue_utilization","occurred_at":"2026-08-31T12:00:00+00:00","process_start_id":"process-1","run_id":"run-1","schema_version":1,"stream_sequence":1,"unit":"ratio","value":0.25}
```

The sequence is scoped to the Caretaker process identity. The application and
run identifiers are included so collectors can partition records across
restarts.

## Dialects

`JSON_LINES` is the lossless local contract and is the default. `DATADOG`
renders DogStatsD gauge lines, for example:

```text
caretaker.logging.queue_utilization:0.25|g|#application_id:payments,region:us-east,unit:ratio,run_id:run-1
```

`SPLUNK_HEC` renders one HTTP Event Collector JSON event per line:

```json
{"event":{"dimensions":{"region":"us-east"},"metric":"caretaker.logging.queue_utilization","stream_sequence":1,"unit":"ratio","value":0.25},"fields":{"process_start_id":"process-1","run_id":"run-1"},"host":"payments","source":"caretaker","sourcetype":"caretaker:metric","time":1788177600.0}
```

`NEW_RELIC` renders one Metric API payload per line:

```json
{"common":{"attributes":{"application_id":"payments","process_start_id":"process-1","region":"us-east","run_id":"run-1","unit":"ratio"},"timestamp":1788177600000},"metrics":[{"name":"caretaker.logging.queue_utilization","type":"gauge","value":0.25}]}
```

The dialects are serialization contracts, not network clients. Transport
authentication, remote retention, replay handling, and collector credentials
remain responsibilities of the external monitoring system. The local writer
does not accept acknowledgements or commands.

## Published metrics

Calling `LoggingRuntime.overhead_status()` publishes the bounded logging-path
snapshot when the stream is enabled. It includes write, flush, queue, failure,
and utilization metrics. Error text is intentionally excluded. The same
snapshot remains available through the existing read-only console/control
status response.

## Policy-controlled process collection and correlation

`logging.metrics` is disabled by default. When enabled, the built-in
`provider_name = "process"` adapter collects an explicitly requested,
non-privileged snapshot of the Caretaker process and publishes it through the
monitoring stream. It does not spawn a collector, grant authority, or read
metrics back as commands. Enabling metrics requires the monitoring stream to
also be enabled.

`sample_interval_seconds` suppresses repeated requests inside the configured
interval, unless the caller explicitly requests an incident/operator capture
with `force=True`. `maximum_samples_per_snapshot` bounds provider output;
truncation is exposed in the read-only adapter status.

Callers may attach bounded identifiers for a target, call, incident, Guard
window, and accepted baseline. Each correlation dimension is independently
policy-controlled. Correlation adds identifiers only; it does not load or
modify the referenced evidence and cannot satisfy a policy or authority gate.

For example:

```python
from caretaker.logging import MetricsCorrelation

runtime.collect_metrics(
    window_start,
    window_end,
    correlation=MetricsCorrelation(
        target_id="payments:checkout",
        incident_id=incident_id,
        guard_window_id=guard_window_id,
        baseline_id=baseline_id,
    ),
)
```

The runtime exposes `metrics_status()` as bounded operational evidence. An
unknown provider name is rejected rather than silently falling back.

## Process metrics

Applications may opt in to `ProcessMetricsProvider` for a bounded snapshot of
the current Caretaker process. The provider reads process-scoped, non-privileged
sources and can publish its samples through `MonitoringStreamWriter.emit_samples`:

```python
provider = ProcessMetricsProvider()
provider.start(MetricsContext(application_id="payments", process_id=os.getpid()))
writer.emit_samples(provider.query(window_start, window_end))
provider.stop()
```

Unavailable process sources are omitted rather than reported as zero. The
provider does not automatically enable monitoring, change policy, or create a
control path. The policy-controlled adapter above is the explicit runtime
integration; host-wide, cgroup-aware, and privileged performance collection
remain outside this contract.
