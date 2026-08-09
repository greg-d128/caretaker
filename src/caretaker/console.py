from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.syntax import Syntax
from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from .logging.ipc import control_request, unix_socket_exists
from .logging.segments import read_segment


def discover_control_socket(data_directory: Path) -> Path | None:
    direct = data_directory / "run" / "control.sock"
    if unix_socket_exists(direct):
        return direct.resolve()
    candidates = [
        path / "run" / "control.sock"
        for path in sorted(data_directory.iterdir())
        if path.is_dir() and unix_socket_exists(path / "run" / "control.sock")
    ] if data_directory.exists() else []
    if len(candidates) == 1:
        return candidates[0].resolve()
    if not candidates:
        return None
    rendered = "\n  ".join(str(path) for path in candidates)
    raise RuntimeError(
        "Multiple Caretaker control sockets were found. Pass --socket or "
        f"--data-directory explicitly:\n  {rendered}"
    )


class ControlRequestError(RuntimeError):
    """Control failure that preserves the structured runtime error object."""

    def __init__(self, error: Any) -> None:
        if isinstance(error, dict):
            self.details = dict(error)
            message = str(
                self.details.get("message")
                or self.details.get("reason")
                or "Caretaker control request failed"
            )
        else:
            message = str(error or "Caretaker control request failed")
            self.details = {"message": message}
        super().__init__(message)


class CaretakerConsoleApp(App):
    TITLE = "Caretaker Console"
    SUB_TITLE = "Runtime inspection and operator control"

    CSS = """
    Screen {
        layout: vertical;
    }
    #operator-status {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $accent;
    }
    #overview-details {
        height: 6;
        padding: 1 2;
    }
    #target-details {
        height: 12;
        border-top: solid $surface-lighten-2;
    }
    TabbedContent {
        height: 1fr;
    }
    .toolbar {
        height: auto;
        padding: 1;
    }
    .toolbar Input {
        width: 1fr;
        min-width: 24;
    }
    .toolbar Button {
        margin-left: 1;
    }
    DataTable, RichLog {
        height: 1fr;
        border: solid $surface-lighten-2;
    }
    #targets-filter {
        height: 3;
        border: none;
        padding: 0 1;
        background: $surface;
    }
    #logs-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 1fr 1fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .logs-pane {
        width: 1fr;
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
        overflow: hidden hidden;
    }
    .logs-pane-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $surface-lighten-2;
    }
    #logs-filter {
        height: 3;
        border: none;
        padding: 0 1;
        background: $surface;
    }
    #logs-table, #logs-output {
        height: 1fr;
        min-height: 0;
        border: none;
    }
    #repair-toolbar {
        height: 3;
        padding: 0 1;
        align-vertical: middle;
        overflow: hidden hidden;
    }
    #repair-refresh {
        width: auto;
        min-width: 16;
        height: 3;
        margin: 0;
    }
    #repair-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 3fr 2fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .repair-pane {
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
        overflow: hidden hidden;
    }
    .repair-pane-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $surface-lighten-2;
    }
    #repair-table, #repair-output {
        height: 1fr;
        min-height: 0;
        border: none;
    }
    #repair-actions {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
        border-top: solid $surface-lighten-2;
    }
    #repair-reason {
        width: 1fr;
        min-width: 24;
    }
    #repair-actions Button {
        width: auto;
        min-width: 12;
        margin-left: 1;
    }

    #policy-summary {
        height: 4;
        padding: 1 2;
        border-bottom: solid $surface-lighten-2;
    }
    #policy-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 3fr 2fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .policy-pane {
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
        overflow: hidden hidden;
    }
    .policy-pane-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $surface-lighten-2;
    }
    #policy-table, #policy-output {
        height: 1fr;
        min-height: 0;
        border: none;
    }
    #policy-lease-row-1, #policy-lease-row-2, #policy-signed-row {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #policy-target { width: 1fr; min-width: 18; }
    #policy-path { width: 2fr; min-width: 24; }
    #policy-value { width: 1fr; min-width: 18; }
    #policy-duration { width: 12; }
    #policy-reason { width: 1fr; min-width: 30; }
    #policy-signed-descriptor { width: 1fr; min-width: 30; }
    #policy-override { width: auto; margin: 0 1; }
    #policy-apply, #policy-apply-signed, #policy-release, #policy-refresh {
        width: auto;
        min-width: 14;
        margin-left: 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, socket_path: Path | None, data_directory: Path) -> None:
        super().__init__()
        self.socket_path = socket_path
        self.data_directory = data_directory
        self._last_status: dict[str, Any] = {}
        self._last_runtime: dict[str, Any] = {}
        self._application_running: bool | None = None
        self._log_records: list[dict[str, Any]] = []
        self._displayed_log_records: list[dict[str, Any]] = []
        self._target_records: list[dict[str, Any]] = []
        self._displayed_target_records: list[dict[str, Any]] = []
        self._repair_records: list[dict[str, Any]] = []
        self._selected_repair_approval: str | None = None
        self._selected_repair_record: dict[str, Any] | None = None
        self._repair_source_view = False
        self._authority_snapshot: dict[str, Any] = {}
        self._authority_rows: list[dict[str, Any]] = []
        self._selected_authority_lease: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Connecting to Caretaker...", id="operator-status")
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield Static("", id="overview-details")
                yield Input(
                    placeholder=(
                        "Filter targets: text, status:validating, mode:automatic, "
                        "authority:approval, guard:yes"
                    ),
                    id="targets-filter",
                )
                table = DataTable(id="targets-table")
                table.cursor_type = "row"
                table.add_columns(
                    "Target", "Mode", "Authority", "Version", "Guard", "Status"
                )
                yield table
                yield RichLog(id="target-details", wrap=True, markup=True)
            with TabPane("Guard", id="guard"):
                with Horizontal(classes="toolbar"):
                    yield Input(placeholder="Target id", id="guard-target")
                    yield Button("Summary", id="guard-summary")
                    yield Button("Events", id="guard-events")
                    yield Button("Deviations", id="guard-deviations")
                    yield Button("Inspections", id="guard-inspections")
                    yield Button("Accept baseline", id="guard-baseline")
                    yield Button("LLM assist", id="guard-assess")
                yield RichLog(id="guard-output", wrap=True, markup=True)
            with TabPane("Repair", id="repair"):
                with Horizontal(id="repair-toolbar"):
                    yield Button("Refresh repair", id="repair-refresh")
                with Grid(id="repair-split"):
                    with Vertical(classes="repair-pane"):
                        yield Static(
                            "Recent and waiting Repair activity",
                            id="repair-list-title",
                            classes="repair-pane-title",
                        )
                        table = DataTable(id="repair-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "State", "Time", "Target", "Description", "Episode")
                        yield table
                    with Vertical(classes="repair-pane"):
                        yield Static(
                            "Selected Repair record",
                            id="repair-detail-title",
                            classes="repair-pane-title",
                        )
                        yield RichLog(id="repair-output", wrap=False, markup=True)
                        with Horizontal(id="repair-actions"):
                            yield Input(
                                placeholder="Rejection reason (used only for Reject)",
                                id="repair-reason",
                            )
                            yield Button(
                                "View source",
                                id="repair-source",
                                disabled=True,
                            )
                            yield Button(
                                "Approve",
                                id="repair-approve",
                                variant="success",
                                disabled=True,
                            )
                            yield Button(
                                "Reject",
                                id="repair-reject",
                                variant="error",
                                disabled=True,
                            )
            with TabPane("Policy", id="policy"):
                yield Static("Authority policy state unavailable", id="policy-summary")
                with Grid(id="policy-split"):
                    with Vertical(classes="policy-pane"):
                        yield Static("Authority layers and runtime leases", classes="policy-pane-title")
                        table = DataTable(id="policy-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Kind", "Authority", "Signature", "Guarantee", "Violations")
                        yield table
                    with Vertical(classes="policy-pane"):
                        yield Static("Selected policy authority record", id="policy-detail-title", classes="policy-pane-title")
                        yield RichLog(id="policy-output", wrap=True, markup=True)
                with Horizontal(id="policy-lease-row-1"):
                    yield Input(placeholder="Target id / glob (required for repair.*)", id="policy-target")
                    yield Input(placeholder="Policy path, e.g. repair.authority", id="policy-path")
                    yield Input(placeholder='Value as JSON or text, e.g. "AUTOMATIC_ELIGIBLE_REPAIRS"', id="policy-value")
                with Horizontal(id="policy-lease-row-2"):
                    yield Input(value="3600", placeholder="Seconds", id="policy-duration")
                    yield Input(placeholder="Incident reason / operator justification", id="policy-reason")
                    yield Checkbox("Explicit override", id="policy-override")
                    yield Button("Apply lease", id="policy-apply", variant="warning")
                    yield Button("Release lease", id="policy-release", disabled=True)
                    yield Button("Refresh", id="policy-refresh")
                with Horizontal(id="policy-signed-row"):
                    yield Input(
                        placeholder="Signed lease descriptor below policy/runtime-leases/",
                        id="policy-signed-descriptor",
                    )
                    yield Button("Apply signed lease", id="policy-apply-signed", variant="primary")
            with TabPane("Investigate", id="investigate"):
                with Horizontal(classes="toolbar"):
                    yield Input(placeholder="Target id (optional)", id="investigate-target")
                    yield Input(placeholder="Ollama model (blank = deterministic)", id="investigate-model")
                    yield Button("Investigate", id="investigate-run", variant="primary")
                with Horizontal(classes="toolbar"):
                    yield Input(
                        value="Investigate the current Caretaker incident",
                        placeholder="Investigation objective",
                        id="investigate-objective",
                    )
                yield Static(
                    "Leave the model blank for deterministic analysis. Entering a model explicitly "
                    "sends the bounded evidence bundle to the configured local Ollama endpoint.",
                    id="investigate-help",
                )
                yield RichLog(id="investigate-output", wrap=True, markup=True)
            with TabPane("Logs", id="logs"):
                with Grid(id="logs-split"):
                    with Vertical(classes="logs-pane"):
                        yield Input(
                            placeholder=(
                                "Filter logs: text, level:warn+, channel:guard, "
                                "target:lab.divide, logger:name"
                            ),
                            id="logs-filter",
                        )
                        table = DataTable(id="logs-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Time", "Level", "Channel", "Target", "Message")
                        yield table
                    with Vertical(classes="logs-pane"):
                        yield Static(
                            "Selected log record | R refreshes",
                            id="logs-detail-title",
                            classes="logs-pane-title",
                        )
                        yield RichLog(id="logs-output", wrap=True, markup=True)
        yield Footer()

    async def on_mount(self) -> None:
        await self.refresh_all()
        self.set_interval(1.0, self.refresh_status)

    async def _request(self, command: str, **payload: Any) -> dict[str, Any]:
        if self.socket_path is None:
            raise ConnectionError("Caretaker supervisor is not running")
        request = {"command": command, **payload}
        response = await asyncio.to_thread(control_request, self.socket_path, request)
        if response.get("ok") is False:
            raise ControlRequestError(
                response.get("error", "Caretaker control request failed")
            )
        return response

    @staticmethod
    def _control_error_payload(
        error: Exception,
        *,
        operation: str,
    ) -> dict[str, Any]:
        if isinstance(error, ControlRequestError):
            payload = dict(error.details)
        else:
            payload = {
                "failure_domain": "CONTROL_TRANSPORT",
                "failure_kind": "transport-error",
                "component": "caretaker.console",
                "stage": "control-request",
                "exception_type": type(error).__name__,
                "message": str(error),
            }
        payload.setdefault("operation", operation)
        payload.setdefault("outcome", "failed")
        return payload

    @staticmethod
    def _metric(runtime: dict[str, Any], key: str) -> Any:
        return runtime.get(key, "-") if runtime else "-"

    def _offline_overview(self, *, reason: str, status_label: str = "OFFLINE") -> None:
        runtime = self._last_runtime
        incident_targets = sorted(
            {
                str(item.get("target_id"))
                for item in runtime.get("active_incidents", ())
                if item.get("target_id")
            }
        ) if runtime else []
        validating = runtime.get("validating_functions", ()) if runtime else ()
        degraded = runtime.get("degraded_components", ()) if runtime else ()
        authority = self._authority_snapshot
        assurance = authority.get("overall_assurance", "-") if authority else "-"
        violations = len(authority.get("violations", ())) if authority else "-"
        self.query_one("#operator-status", Static).update(
            f"Status {status_label}  |  "
            f"Last alert {self._metric(runtime, 'alert_level')}  |  "
            f"Last incidents {self._metric(runtime, 'active_incident_count')}  |  "
            f"Last validating {self._metric(runtime, 'validation_count')}  |  "
            f"Last approvals {self._metric(runtime, 'pending_approval_count')}  |  "
            f"Policy {assurance}  |  Violations {violations}"
        )
        self._clear_repair_selection()
        details = [
            f"Application: stopped / unavailable ({reason})",
            "Live runtime state is unavailable. Last successfully read runtime data is retained on screen.",
            "Last active incident targets: "
            f"{', '.join(incident_targets) if incident_targets else 'none / unknown'}",
            f"Last validating functions: {', '.join(validating) if validating else 'none / unknown'}",
            f"Last degraded capabilities: {', '.join(degraded) if degraded else 'none / unknown'}",
            "Persisted Caretaker logs remain available from the Logs tab.",
        ]
        self.query_one("#overview-details", Static).update("\n".join(details))

    async def refresh_status(self) -> None:
        if self.socket_path is None:
            self._application_running = False
            self._offline_overview(reason="no active caretaker-run control socket")
            return
        try:
            status = await self._request("status")
        except Exception:
            self._application_running = False
            self._offline_overview(reason="Caretaker supervisor control socket is unavailable")
            return

        self._last_status = status
        running = bool(status.get("application_running"))
        self._application_running = running
        runtime_value = status.get("runtime")
        runtime = runtime_value if isinstance(runtime_value, dict) else {}
        if runtime:
            self._last_runtime = dict(runtime)

        if not running:
            self._offline_overview(
                reason="application process has exited",
                status_label="STOPPED",
            )
            return

        workers = status.get("workers") or []
        unhealthy = [
            item for item in workers
            if str(item.get("state", "")).upper() not in {"HEALTHY", "WORKERSTATE.HEALTHY"}
        ]
        validating = runtime.get("validating_functions") or []
        incidents = runtime.get("active_incidents") or []
        incident_targets = sorted(
            {str(item.get("target_id")) for item in incidents if item.get("target_id")}
        )
        degraded = runtime.get("degraded_components") or []
        authority_summary = status.get("authority_policy") or {}
        assurance = authority_summary.get("overall_assurance", "UNCONFIGURED")
        runtime_policy_match = authority_summary.get("runtime_matches_supervisor")
        displayed_assurance = "RUNTIME_TAMPER" if runtime_policy_match is False else assurance
        policy_violations = authority_summary.get("violations", 0)
        line = (
            f"Status {runtime.get('current_status', 'STARTING')}  |  "
            f"Alert {runtime.get('alert_level', 'NONE')}  |  "
            f"Incidents {runtime.get('active_incident_count', 0)}  |  "
            f"Validating {runtime.get('validation_count', 0)}  |  "
            f"Approvals {runtime.get('pending_approval_count', 0)}  |  "
            f"Policy {displayed_assurance}  |  Violations {policy_violations}  |  "
            f"Worker issues {len(unhealthy)}"
        )
        self.query_one("#operator-status", Static).update(line)
        details = [
            f"Application PID: {status.get('application_pid')}   running=True",
            f"Active incident targets: {', '.join(incident_targets) if incident_targets else 'none'}",
            f"Validating functions: {', '.join(validating) if validating else 'none'}",
            f"Degraded capabilities: {', '.join(degraded) if degraded else 'none'}",
            "Runtime policy matches supervisor: "
            + ("yes" if runtime_policy_match is True else "NO - POLICY TAMPER DETECTED" if runtime_policy_match is False else "unknown"),
        ]
        self.query_one("#overview-details", Static).update("\n".join(details))

    @staticmethod
    def _enum_name(value: Any) -> str:
        text = str(value or "").strip()
        if "." in text:
            text = text.rsplit(".", 1)[-1]
        return text.upper()

    @classmethod
    def _target_runtime_states(
        cls, state_response: dict[str, Any] | None
    ) -> tuple[str, str]:
        if not isinstance(state_response, dict):
            return "", ""
        state = state_response.get("state")
        if not isinstance(state, dict):
            return "", ""
        slot = state.get("slot")
        if not isinstance(slot, dict):
            return "", ""

        slot_state = cls._enum_name(slot.get("state"))
        candidate_state = cls._enum_name(
            slot.get("candidate_state") or slot.get("current_candidate_state")
        )

        current = slot.get("current") or slot.get("current_version")
        if not candidate_state and isinstance(current, dict):
            candidate_state = cls._enum_name(current.get("candidate_state"))

        observation = slot.get("observation")
        if isinstance(observation, dict):
            observation_state = cls._enum_name(observation.get("state"))
            if observation_state:
                candidate_state = observation_state
        elif not candidate_state:
            candidate_state = cls._enum_name(slot.get("observation_state"))

        return slot_state, candidate_state

    @classmethod
    def _target_status(cls, target: dict[str, Any]) -> str:
        slot_state = cls._enum_name(target.get("slot_state"))
        candidate_state = cls._enum_name(target.get("candidate_state"))
        if target.get("repair_in_progress") or slot_state == "REPAIRING":
            return "REPAIRING"
        if slot_state == "CANDIDATE_ACTIVE" or candidate_state == "ACTIVE_PROBATION":
            # CANDIDATE_ACTIVE is the live post-activation observation period. Present it
            # as VALIDATING in the operator overview while preserving the raw states in
            # target-detail JSON.
            return "VALIDATING"
        if slot_state:
            return slot_state
        if candidate_state:
            return candidate_state
        return "READY"

    @classmethod
    def _target_matches_filter(cls, target: dict[str, Any], expression: str) -> bool:
        tokens = [token for token in expression.casefold().split() if token]
        if not tokens:
            return True
        fields = {
            "target": str(target.get("target_id") or "").casefold(),
            "status": str(target.get("status") or "").casefold(),
            "state": " ".join(
                (
                    str(target.get("slot_state") or ""),
                    str(target.get("candidate_state") or ""),
                )
            ).casefold(),
            "mode": str(target.get("repair_mode") or "").casefold(),
            "authority": str(target.get("repair_authority") or "").casefold(),
            "guard": ("yes" if target.get("guard_enabled") else "no"),
            "version": str(
                target.get("function_version")
                if target.get("function_version") is not None
                else ""
            ).casefold(),
        }
        searchable = " ".join(
            (
                fields["target"],
                fields["status"],
                fields["state"],
                fields["mode"],
                fields["authority"],
                fields["guard"],
                fields["version"],
                str(target.get("display_name") or "").casefold(),
                str(target.get("module") or "").casefold(),
                str(target.get("qualified_name") or "").casefold(),
            )
        )
        for token in tokens:
            if ":" not in token:
                if token not in searchable:
                    return False
                continue
            field, value = token.split(":", 1)
            if not value:
                continue
            if field in fields:
                if value not in fields[field]:
                    return False
                continue
            if token not in searchable:
                return False
        return True

    def _apply_target_filter(self) -> None:
        expression = self.query_one("#targets-filter", Input).value.strip()
        self._displayed_target_records = [
            target
            for target in self._target_records
            if self._target_matches_filter(target, expression)
        ]
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        for target in self._displayed_target_records:
            target_id = str(target.get("target_id", ""))
            table.add_row(
                target_id,
                str(target.get("repair_mode") or "-"),
                str(target.get("repair_authority") or "-"),
                str(
                    target.get("function_version")
                    if target.get("function_version") is not None
                    else "-"
                ),
                "yes" if target.get("guard_enabled") else "no",
                str(target.get("status") or "READY"),
                key=target_id,
            )

        details = self.query_one("#target-details", RichLog)
        details.clear()
        shown = len(self._displayed_target_records)
        total = len(self._target_records)
        if shown:
            details.write(
                f"Showing {shown}/{total} targets. Select a target to inspect its exact "
                "FunctionSlot state and effective policy."
            )
        elif total:
            details.write("No targets match the current filter.")
        else:
            details.write("No runtime targets were returned.")

    async def refresh_targets(self) -> None:
        if not self._application_running:
            details = self.query_one("#target-details", RichLog)
            if self._target_records:
                self._apply_target_filter()
                details.write(
                    "Application is stopped. The target table contains the last live snapshot "
                    "captured by this console; live target state and policy inspection are unavailable."
                )
            else:
                details.clear()
                details.write(
                    "Application is stopped and no live target snapshot is available. "
                    "Persisted evidence remains available in Logs."
                )
            return
        response = await self._request("runtime-targets")
        self._target_records = [
            dict(target)
            for target in response.get("targets", ())
            if isinstance(target, dict)
        ]
        state_results = await asyncio.gather(
            *(
                self._request(
                    "runtime-target-state",
                    target=str(target.get("target_id") or ""),
                )
                for target in self._target_records
                if target.get("target_id")
            ),
            return_exceptions=True,
        )
        state_index = 0
        for target in self._target_records:
            if not target.get("target_id"):
                target["slot_state"] = ""
                target["candidate_state"] = ""
                target["status"] = self._target_status(target)
                continue
            state_result = state_results[state_index]
            state_index += 1
            if isinstance(state_result, Exception):
                slot_state, candidate_state = "", ""
            else:
                slot_state, candidate_state = self._target_runtime_states(state_result)
            target["slot_state"] = slot_state
            target["candidate_state"] = candidate_state
            target["status"] = self._target_status(target)
        self._apply_target_filter()

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "logs-table":
            row = event.data_table.get_row(event.row_key)
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._displayed_log_records[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            self.query_one("#logs-detail-title", Static).update(
                f"Log record {record_number} | "
                f"{record.get('channel', '-')} | {record.get('target_id') or 'no target'}"
            )
            self._write_json("#logs-output", record)
            return

        if event.data_table.id == "repair-table":
            row = event.data_table.get_row(event.row_key)
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._repair_records[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            self._selected_repair_record = record
            self._repair_source_view = False
            self._selected_repair_approval = (
                str(record.get("episode_id"))
                if record.get("record_kind") == "pending_approval" and record.get("episode_id")
                else None
            )
            actionable = self._selected_repair_approval is not None and bool(self._application_running)
            self.query_one("#repair-approve", Button).disabled = not actionable
            self.query_one("#repair-reject", Button).disabled = not actionable
            source_button = self.query_one("#repair-source", Button)
            source_button.label = "View source"
            source_button.disabled = self._repair_source(record) is None
            if record.get("record_kind") == "pending_approval":
                title = f"Pending approval | {record.get('target_id', '-')}"
            elif record.get("record_kind") == "control_error":
                title = f"Repair query error | {record.get('target_id', '-')}"
            else:
                title = f"Repair event | {record.get('target_id', '-')}"
            self.query_one("#repair-detail-title", Static).update(title)
            self._write_json("#repair-output", record.get("payload", record))
            return

        if event.data_table.id == "policy-table":
            row = event.data_table.get_row(event.row_key)
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._authority_rows[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            self._selected_authority_lease = str(record.get("lease_id")) if record.get("lease_id") else None
            self.query_one("#policy-release", Button).disabled = self._selected_authority_lease is None
            self.query_one("#policy-detail-title", Static).update(
                f"{record.get('kind', 'policy')} | {record.get('authority_id') or 'not configured'}"
            )
            self._write_json("#policy-output", record)
            return

        if event.data_table.id != "targets-table":
            return
        row = event.data_table.get_row(event.row_key)
        if not row:
            return
        target_id = str(row[0])
        if not self._application_running:
            details = self.query_one("#target-details", RichLog)
            details.clear()
            details.write(
                f"{target_id}: application is stopped. This row is the last live snapshot; "
                "current FunctionSlot state and policy cannot be queried."
            )
            return
        try:
            state, policy = await asyncio.gather(
                self._request("runtime-target-state", target=target_id),
                self._request("runtime-target-policy", target=target_id),
            )
            self._write_json(
                "#target-details",
                {
                    "target": target_id,
                    "state": state.get("state"),
                    "policy": policy.get("policy"),
                },
            )
        except Exception as exc:
            self._write_json(
                "#target-details",
                {"error": f"{type(exc).__name__}: {exc}", "target": target_id},
            )

    async def refresh_all(self) -> None:
        await self.refresh_authority()
        await self.refresh_status()
        if self._application_running:
            try:
                await self.refresh_targets()
            except Exception as exc:
                details = self.query_one("#target-details", RichLog)
                details.clear()
                details.write(f"Unable to refresh live target state: {type(exc).__name__}: {exc}")
            try:
                await self.refresh_repair()
            except Exception as exc:
                self._show_repair_message(
                    f"Unable to refresh live Repair state: {type(exc).__name__}: {exc}"
                )
        else:
            await self.refresh_targets()
            await self.refresh_repair()
        await self.refresh_logs()

    async def action_refresh(self) -> None:
        await self.refresh_all()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "logs-filter":
            self._apply_log_filter()
        elif event.input.id == "targets-filter":
            self._apply_target_filter()

    @staticmethod
    def _log_level(severity: Any) -> str:
        try:
            value = int(severity)
        except (TypeError, ValueError):
            return str(severity or "-")
        if value >= 50:
            return "CRIT"
        if value >= 40:
            return "ERROR"
        if value >= 30:
            return "WARN"
        if value >= 20:
            return "INFO"
        if value >= 10:
            return "DEBUG"
        return str(value)

    @staticmethod
    def _compact_log_text(value: Any, *, limit: int) -> str:
        text = " ".join(str(value or "").split())
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 1)] + "…"

    @staticmethod
    def _log_timestamp(record: dict[str, Any]) -> float:
        value = str(record.get("occurred_at") or "").strip()
        if not value:
            return float("-inf")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            return float("-inf")

    @classmethod
    def _sorted_log_records(cls, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Do not trust segment or IPC return order. Multiple writers/segments may
        # be interleaved, so render by event time with a deterministic JSON
        # tie-breaker for records that share the same timestamp.
        return sorted(
            records,
            key=lambda record: (
                cls._log_timestamp(record),
                str(record.get("channel") or ""),
                str(record.get("target_id") or ""),
                str(record.get("logger") or ""),
                str(record.get("message") or ""),
            ),
            reverse=True,
        )

    @classmethod
    def _log_matches_filter(cls, record: dict[str, Any], expression: str) -> bool:
        tokens = [token for token in expression.casefold().split() if token]
        if not tokens:
            return True

        level_name = cls._log_level(record.get("severity")).casefold()
        try:
            severity = int(record.get("severity"))
        except (TypeError, ValueError):
            severity = -1
        level_values = {
            "debug": 10,
            "info": 20,
            "warn": 30,
            "warning": 30,
            "error": 40,
            "crit": 50,
            "critical": 50,
        }
        fields = {
            "channel": str(record.get("channel") or "").casefold(),
            "target": str(record.get("target_id") or "").casefold(),
            "logger": str(record.get("logger") or "").casefold(),
            "message": str(record.get("message") or "").casefold(),
        }
        searchable = json.dumps(record, default=str).casefold()

        for token in tokens:
            if ":" not in token:
                if token not in searchable:
                    return False
                continue
            field, value = token.split(":", 1)
            if not value:
                continue
            if field == "level":
                minimum = value.endswith("+")
                normalized = value[:-1] if minimum else value
                wanted = level_values.get(normalized)
                if wanted is None:
                    if normalized not in level_name:
                        return False
                elif minimum:
                    if severity < wanted:
                        return False
                else:
                    normalized_name = {
                        "warning": "warn",
                        "critical": "crit",
                    }.get(normalized, normalized)
                    if level_name != normalized_name:
                        return False
                continue
            if field in fields:
                if value not in fields[field]:
                    return False
                continue
            # Unknown prefixes remain useful as ordinary full-record search
            # terms rather than unexpectedly hiding every row.
            if token not in searchable:
                return False
        return True

    def _apply_log_filter(self) -> None:
        expression = self.query_one("#logs-filter", Input).value.strip()
        self._displayed_log_records = [
            record for record in self._log_records
            if self._log_matches_filter(record, expression)
        ]

        table = self.query_one("#logs-table", DataTable)
        table.clear()
        for index, record in enumerate(self._displayed_log_records, start=1):
            occurred_at = str(record.get("occurred_at") or "")
            timestamp = occurred_at[:19].replace("T", " ") if occurred_at else "-"
            table.add_row(
                index,
                timestamp,
                self._log_level(record.get("severity")),
                self._compact_log_text(record.get("channel"), limit=18) or "-",
                self._compact_log_text(record.get("target_id"), limit=28) or "-",
                self._compact_log_text(record.get("message"), limit=80) or "-",
            )

        detail = self.query_one("#logs-output", RichLog)
        detail.clear()
        shown = len(self._displayed_log_records)
        total = len(self._log_records)
        self.query_one("#logs-detail-title", Static).update(
            f"Selected log record | Showing {shown}/{total} | R refreshes"
        )
        if self._displayed_log_records:
            detail.write("Select a log record from the list to inspect its full JSON.")
        elif total:
            detail.write("No log records match the current filter.")
        else:
            detail.write("No log records were returned.")

    async def refresh_logs(self) -> None:
        records: list[dict[str, Any]]
        try:
            response = await self._request("logs", limit=200)
            records = [dict(record) for record in response.get("records", []) if isinstance(record, dict)]
        except Exception:
            records = self._local_log_records(200)
        self._log_records = self._sorted_log_records(records)
        self._apply_log_filter()

    def _local_log_records(self, limit: int) -> list[dict[str, Any]]:
        event_directories = []
        direct = self.data_directory / "application" / "events"
        if direct.exists():
            event_directories.append(direct)
        event_directories.extend(
            path for path in self.data_directory.glob("*/application/events")
            if path not in event_directories
        )
        paths: list[Path] = []
        for directory in event_directories:
            paths.extend(directory.glob("*.ctlog"))
            paths.extend(directory.glob("*.ctlog.gz"))
        envelopes = []
        for path in sorted(paths)[-16:]:
            try:
                envelopes.extend(read_segment(path))
            except Exception:
                continue
        return [
            {
                "occurred_at": item.occurred_at.isoformat(),
                "severity": item.severity,
                "channel": item.channel.name,
                "logger": item.logger_name,
                "message": item.formatted_message or item.message_template,
                "target_id": str(item.target_id) if item.target_id else None,
                "fields": dict(item.fields),
            }
            for item in envelopes[-max(1, limit):]
        ]

    @staticmethod
    def _repair_state(event_type: str) -> str:
        value = event_type.lower()
        if value == "incident.created":
            return "INCIDENT"
        if value == "repair.episode_started":
            return "ACTIVE"
        if "operator_approved" in value or "retry_succeeded" in value:
            return "REPAIRED"
        if "operator_rejected" in value:
            return "REJECTED"
        if "rolled_back" in value:
            return "ROLLBACK"
        if "failed" in value:
            return "FAILED"
        if "suppressed" in value:
            return "BLOCKED"
        if "queued" in value:
            return "QUEUED"
        return "EVENT"

    @staticmethod
    def _repair_description(event: dict[str, Any]) -> str:
        event_type = str(event.get("event_type") or "repair event")
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        if event_type == "incident.created":
            trigger = details.get("trigger")
            return f"Incident created{f' ({trigger})' if trigger else ''}"
        if event_type == "repair.episode_started":
            return "Repair episode started"
        if event_type == "repair.operator_approved":
            return "Operator approved validated repair"
        if event_type == "repair.operator_rejected":
            return f"Operator rejected repair: {details.get('reason', 'no reason recorded')}"
        if event_type == "repair.retry_succeeded":
            return "Repair activated and retry succeeded"
        if event_type == "repair.retry_failed":
            return str(details.get("exception") or "Repair retry failed")
        if event_type == "repair.retry_contract_failed":
            return str(details.get("reason") or "Repaired result failed contract validation")
        if event_type == "repair.suppressed_by_limits":
            return "Repair suppressed by configured limits"
        if event_type == "candidate.synthesis_failed":
            return str(details.get("error") or "Candidate synthesis failed")
        if event_type == "guard.repair_queued":
            explanations = details.get("explanations") or []
            return str(explanations[0]) if explanations else "Guard queued a Repair episode"
        return event_type.replace(".", " / ")

    @staticmethod
    def _repair_source(record: dict[str, Any] | None) -> str | None:
        if not isinstance(record, dict):
            return None
        payload = record.get("payload", record)
        if not isinstance(payload, dict):
            return None
        source = payload.get("source")
        return source if isinstance(source, str) and source.strip() else None

    def _clear_repair_selection(self) -> None:
        self._selected_repair_approval = None
        self._selected_repair_record = None
        self._repair_source_view = False
        self.query_one("#repair-approve", Button).disabled = True
        self.query_one("#repair-reject", Button).disabled = True
        source_button = self.query_one("#repair-source", Button)
        source_button.disabled = True
        source_button.label = "View source"

    def _show_selected_repair_json(self) -> None:
        if self._selected_repair_record is None:
            return
        payload = self._selected_repair_record.get(
            "payload", self._selected_repair_record
        )
        self._write_json("#repair-output", payload)

    def _show_selected_repair_source(self) -> None:
        source = self._repair_source(self._selected_repair_record)
        if source is None:
            return
        output = self.query_one("#repair-output", RichLog)
        output.clear()
        output.write(
            Syntax(
                source,
                "python",
                line_numbers=True,
                word_wrap=False,
                indent_guides=True,
            )
        )

    def _show_repair_message(self, message: str) -> None:
        output = self.query_one("#repair-output", RichLog)
        output.clear()
        output.write(message)

    async def refresh_repair(self) -> None:
        if not self._application_running:
            self._clear_repair_selection()
            if self._repair_records:
                self.query_one("#repair-list-title", Static).update(
                    "Last live Repair activity (application stopped)"
                )
                self._show_repair_message(
                    "Application is stopped. The list contains the last live Repair snapshot "
                    "captured by this console. Approval actions are unavailable; "
                    "use Logs for persisted evidence."
                )
            else:
                self.query_one("#repair-list-title", Static).update(
                    "Repair activity (live runtime unavailable)"
                )
                self._show_repair_message(
                    "Application is stopped and no live Repair snapshot is available. "
                    "Use the Logs tab to inspect persisted Caretaker evidence."
                )
            return

        events_result, approvals_result = await asyncio.gather(
            self._request("runtime-repair-events", limit=100),
            self._request("runtime-repair-approvals"),
            return_exceptions=True,
        )

        errors: list[tuple[str, Exception]] = []
        if isinstance(events_result, Exception):
            events: list[dict[str, Any]] = []
            errors.append(("runtime-repair-events", events_result))
        else:
            events = [
                item for item in events_result.get("events", ()) if isinstance(item, dict)
            ]

        if isinstance(approvals_result, Exception):
            approvals: list[dict[str, Any]] = []
            errors.append(("runtime-repair-approvals", approvals_result))
        else:
            approvals = [
                item
                for item in approvals_result.get("approvals", ())
                if isinstance(item, dict)
            ]

        records: list[dict[str, Any]] = []
        for approval in approvals:
            episode_id = str(approval.get("episode_id") or "")
            records.append({
                "record_kind": "pending_approval",
                "state": "WAITING",
                "timestamp": "",
                "target_id": str(approval.get("target_id") or "-"),
                "description": (
                    "Validated repair awaiting approval: "
                    f"{approval.get('reason') or 'operator review required'}"
                ),
                "episode_id": episode_id,
                "payload": approval,
            })
        for operation, error in errors:
            payload = self._control_error_payload(error, operation=operation)
            records.append({
                "record_kind": "control_error",
                "state": "ERROR",
                "timestamp": str(payload.get("occurred_at") or ""),
                "target_id": str(payload.get("target_id") or "-"),
                "description": (
                    f"{operation} failed: "
                    f"{payload.get('exception_type', 'error')}: "
                    f"{payload.get('message', 'Caretaker control request failed')}"
                ),
                "episode_id": str(payload.get("episode_id") or ""),
                "payload": payload,
            })
        for item in reversed(events):
            records.append({
                "record_kind": "event",
                "state": self._repair_state(str(item.get("event_type") or "")),
                "timestamp": str(item.get("timestamp") or ""),
                "target_id": str(item.get("target_id") or "-"),
                "description": self._repair_description(item),
                "episode_id": str(item.get("episode_id") or ""),
                "payload": item,
            })
        self._repair_records = records
        self._clear_repair_selection()
        self.query_one("#repair-list-title", Static).update(
            "Repair activity (partial results; inspect ERROR record)"
            if errors
            else "Recent and waiting Repair activity"
        )
        self.query_one("#repair-detail-title", Static).update("Selected Repair record")

        table = self.query_one("#repair-table", DataTable)
        table.clear()
        for index, record in enumerate(records, start=1):
            timestamp = record["timestamp"]
            rendered_time = timestamp[:19].replace("T", " ") if timestamp else "-"
            table.add_row(
                index,
                record["state"],
                rendered_time,
                self._compact_log_text(record["target_id"], limit=28),
                self._compact_log_text(record["description"], limit=72),
                self._compact_log_text(record["episode_id"], limit=12) or "-",
            )

        if errors:
            self._show_repair_message(
                "Partial Repair data returned. Pending approvals remain available when "
                "their query succeeded; select an ERROR row for structured diagnostics."
            )
        else:
            self._show_repair_message(
                "Select a waiting approval or recent Repair event to inspect it. "
                "Validated replacement source can be reviewed as formatted Python before approval."
                if records else "No Repair events or pending approvals were returned."
            )

    def _local_authority_snapshot(self) -> dict[str, Any]:
        candidates = [self.data_directory / "policy" / "authority-effective.json"]
        candidates.extend(self.data_directory.glob("*/policy/authority-effective.json"))
        for path in candidates:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
            if isinstance(value, dict):
                return value
        return {}

    async def refresh_authority(self) -> None:
        try:
            response = await self._request("authority-status")
            snapshot = {key: value for key, value in response.items() if key != "ok"}
        except Exception:
            snapshot = self._local_authority_snapshot()
        self._authority_snapshot = snapshot
        statuses = [dict(item) for item in snapshot.get("layer_status", ()) if isinstance(item, dict)]
        layers_by_id = {
            str(item.get("authority_id")): dict(item)
            for item in snapshot.get("layers", ())
            if isinstance(item, dict) and item.get("authority_id")
        }
        verifications_by_id = {
            str(item.get("authority_id")): dict(item)
            for item in snapshot.get("verifications", ())
            if isinstance(item, dict) and item.get("authority_id")
        }
        leases_by_id = {
            str(item.get("lease_id")): dict(item)
            for item in snapshot.get("runtime_leases", ())
            if isinstance(item, dict) and item.get("lease_id")
        }
        violation_list = [
            dict(item) for item in snapshot.get("violations", ()) if isinstance(item, dict)
        ]
        rows: list[dict[str, Any]] = []
        for status in statuses:
            record = dict(status)
            authority_id = status.get("authority_id")
            lease_id = status.get("lease_id")
            if authority_id and str(authority_id) in layers_by_id:
                record["layer"] = layers_by_id[str(authority_id)]
                record["verification"] = verifications_by_id.get(str(authority_id))
                record["constraint_violations"] = [
                    item for item in violation_list
                    if str(item.get("authority_id")) == str(authority_id)
                ]
            if lease_id and str(lease_id) in leases_by_id:
                record["runtime_lease"] = leases_by_id[str(lease_id)]
            rows.append(record)
        self._authority_rows = rows
        self._selected_authority_lease = None
        self.query_one("#policy-release", Button).disabled = True

        assurance = snapshot.get("overall_assurance", "UNCONFIGURED") if snapshot else "UNAVAILABLE"
        generation = snapshot.get("generation", "-") if snapshot else "-"
        fingerprint = str(snapshot.get("fingerprint", "-")) if snapshot else "-"
        violations = snapshot.get("violations", ()) if snapshot else ()
        runtime_match = snapshot.get("runtime_matches_supervisor") if snapshot else None
        runtime_match_text = (
            "MATCH" if runtime_match is True
            else "MISMATCH - POLICY TAMPER" if runtime_match is False
            else "UNAVAILABLE"
        )
        self.query_one("#policy-summary", Static).update(
            f"Overall assurance: {assurance}   Generation: {generation}   "
            f"Violations: {len(violations)}   Runtime: {runtime_match_text}\n"
            f"Effective fingerprint: {fingerprint}"
        )
        table = self.query_one("#policy-table", DataTable)
        table.clear()
        for index, record in enumerate(rows, start=1):
            table.add_row(
                index,
                str(record.get("kind") or "-"),
                self._compact_log_text(record.get("authority_id"), limit=28) or "-",
                str(record.get("signature") or "-"),
                str(record.get("guarantee") or "-"),
                str(record.get("violations", 0)),
            )
        output = self.query_one("#policy-output", RichLog)
        output.clear()
        if snapshot:
            if violations:
                output.write("Policy guarantee violations are present. Select a layer to inspect it; full violations follow.")
                output.write(json.dumps(violations, indent=2, sort_keys=True, default=str))
            elif rows:
                output.write("Select an authority layer or runtime lease to inspect provenance and guarantee state.")
            else:
                output.write("No authority layers are configured. Caretaker is operating without policy-authority assurance.")
        else:
            output.write("No live or persisted authority-policy snapshot is available.")

    @staticmethod
    def _parse_policy_value(text: str) -> Any:
        stripped = text.strip()
        if not stripped:
            raise ValueError("Enter a policy value")
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return stripped

    def _target(self, input_id: str) -> str:
        value = self.query_one(input_id, Input).value.strip()
        if not value:
            raise ValueError("Enter a target id first")
        return value

    def _write_json(self, log_id: str, value: Any) -> None:
        log = self.query_one(log_id, RichLog)
        log.clear()
        log.write(json.dumps(value, indent=2, sort_keys=True, default=str))

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id or ""
        try:
            if button.startswith("guard-"):
                target = self._target("#guard-target")
                command_map = {
                    "guard-summary": "runtime-guard-summary",
                    "guard-events": "runtime-guard-events",
                    "guard-deviations": "runtime-guard-deviations",
                    "guard-inspections": "runtime-guard-inspections",
                    "guard-baseline": "runtime-guard-baseline-accept",
                    "guard-assess": "runtime-guard-assess",
                }
                response = await self._request(command_map[button], target=target, limit=100)
                self._write_json("#guard-output", response)
                return
            if button == "repair-refresh":
                await self.refresh_repair()
                return
            if button == "repair-source":
                source = self._repair_source(self._selected_repair_record)
                if source is None:
                    raise ValueError("Selected Repair record does not contain replacement source")
                if self._repair_source_view:
                    self._repair_source_view = False
                    event.button.label = "View source"
                    self._show_selected_repair_json()
                else:
                    self._repair_source_view = True
                    event.button.label = "View JSON"
                    self._show_selected_repair_source()
                return
            if button in {"repair-approve", "repair-reject"}:
                episode = self._selected_repair_approval
                if not episode:
                    raise ValueError("Select a pending Repair approval first")
                if not self._application_running:
                    raise RuntimeError("The application is stopped; Repair approvals require a live runtime")
                if button == "repair-approve":
                    response = await self._request("runtime-repair-approve", episode_id=episode)
                else:
                    reason = self.query_one("#repair-reason", Input).value.strip()
                    response = await self._request(
                        "runtime-repair-reject",
                        episode_id=episode,
                        reason=reason or "operator rejected candidate from Caretaker console",
                    )
                self._write_json("#repair-output", response)
                await self.refresh_status()
                await self.refresh_targets()
                await self.refresh_repair()
                return
            if button == "policy-refresh":
                await self.refresh_authority()
                return
            if button == "policy-apply":
                path = self.query_one("#policy-path", Input).value.strip()
                if not path:
                    raise ValueError("Enter a policy path")
                target = self.query_one("#policy-target", Input).value.strip()
                value = self._parse_policy_value(self.query_one("#policy-value", Input).value)
                reason = self.query_one("#policy-reason", Input).value.strip()
                if not reason:
                    raise ValueError("Temporary policy leases require an incident/operator reason")
                duration = int(self.query_one("#policy-duration", Input).value.strip() or "3600")
                override = self.query_one("#policy-override", Checkbox).value
                response = await self._request(
                    "authority-lease-acquire",
                    path=path,
                    value=value,
                    target=target or None,
                    reason=reason,
                    duration_seconds=duration,
                    override_constraints=override,
                )
                self._write_json("#policy-output", response)
                await self.refresh_authority()
                await self.refresh_status()
                await self.refresh_targets()
                return
            if button == "policy-apply-signed":
                descriptor = self.query_one("#policy-signed-descriptor", Input).value.strip()
                if not descriptor:
                    raise ValueError(
                        "Enter a signed lease descriptor filename from policy/runtime-leases/"
                    )
                reason = self.query_one("#policy-reason", Input).value.strip()
                response = await self._request(
                    "authority-lease-acquire-signed",
                    descriptor=descriptor,
                    reason=reason or "signed runtime policy lease",
                )
                self._write_json("#policy-output", response)
                await self.refresh_authority()
                await self.refresh_status()
                await self.refresh_targets()
                return
            if button == "policy-release":
                if not self._selected_authority_lease:
                    raise ValueError("Select a runtime policy lease first")
                response = await self._request(
                    "authority-lease-release", lease_id=self._selected_authority_lease
                )
                self._write_json("#policy-output", response)
                await self.refresh_authority()
                await self.refresh_status()
                await self.refresh_targets()
                return
            if button == "investigate-run":
                target = self.query_one("#investigate-target", Input).value.strip()
                model = self.query_one("#investigate-model", Input).value.strip()
                objective = self.query_one("#investigate-objective", Input).value.strip()
                response = await self._request(
                    "investigate",
                    target=target or None,
                    model=model or None,
                    objective=objective or "Investigate the current Caretaker incident",
                    minutes=15,
                )
                self._write_json("#investigate-output", response)
                return
        except Exception as exc:
            output = "#guard-output" if button.startswith("guard-") else "#repair-output"
            if button == "investigate-run":
                output = "#investigate-output"
            elif button.startswith("policy-"):
                output = "#policy-output"
            self._write_json(output, {"error": f"{type(exc).__name__}: {exc}"})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caretaker-console")
    parser.add_argument("--socket", type=Path, help="explicit caretaker-run control socket")
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory or parent directory containing one active run",
    )
    args = parser.parse_args(argv)
    data_directory = args.data_directory.expanduser().resolve()
    try:
        socket_path = (
            args.socket.expanduser().resolve()
            if args.socket
            else discover_control_socket(data_directory)
        )
    except RuntimeError as exc:
        parser.error(str(exc))
        return 2
    CaretakerConsoleApp(socket_path, data_directory).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
