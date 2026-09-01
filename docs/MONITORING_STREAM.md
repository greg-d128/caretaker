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
