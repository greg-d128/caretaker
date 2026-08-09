from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static, TabbedContent, TabPane

from .logging.ipc import control_request


def discover_control_socket(data_directory: Path) -> Path:
    direct = data_directory / "run" / "control.sock"
    if direct.exists():
        return direct.resolve()
    candidates = sorted(data_directory.glob("*/run/control.sock"))
    if len(candidates) == 1:
        return candidates[0].resolve()
    if not candidates:
        raise FileNotFoundError(
            f"No Caretaker control socket found under {data_directory}. "
            "Start the application with caretaker-run or pass --socket."
        )
    rendered = "\n  ".join(str(path) for path in candidates)
    raise RuntimeError(
        "Multiple Caretaker control sockets were found. Pass --socket or "
        f"--data-directory explicitly:\n  {rendered}"
    )


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
    #logs-toolbar {
        height: 3;
        padding: 0 1;
        align-vertical: middle;
        overflow: hidden hidden;
    }
    #logs-refresh {
        width: auto;
        min-width: 16;
        height: 3;
        margin: 0;
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
    #logs-table, #logs-output {
        height: 1fr;
        min-height: 0;
        border: none;
    }
    #repair-episode, #repair-reason {
        width: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
    ]

    def __init__(self, socket_path: Path) -> None:
        super().__init__()
        self.socket_path = socket_path
        self._last_status: dict[str, Any] = {}
        self._log_records: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Connecting to Caretaker...", id="operator-status")
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield Static("", id="overview-details")
                table = DataTable(id="targets-table")
                table.cursor_type = "row"
                table.add_columns(
                    "Target", "Mode", "Authority", "Version", "Guard", "Slot state"
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
                with Horizontal(classes="toolbar"):
                    yield Input(placeholder="Target id (optional for events)", id="repair-target")
                    yield Button("Events", id="repair-events")
                    yield Button("Approvals", id="repair-approvals")
                with Horizontal(classes="toolbar"):
                    yield Input(placeholder="Episode UUID", id="repair-episode")
                    yield Input(placeholder="Rejection reason", id="repair-reason")
                    yield Button("Approve", id="repair-approve", variant="success")
                    yield Button("Reject", id="repair-reject", variant="error")
                yield RichLog(id="repair-output", wrap=True, markup=True)
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
                with Horizontal(id="logs-toolbar"):
                    yield Button("Refresh logs", id="logs-refresh")
                with Grid(id="logs-split"):
                    with Vertical(classes="logs-pane"):
                        yield Static("Log records (newest first)", classes="logs-pane-title")
                        table = DataTable(id="logs-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Time", "Level", "Channel", "Target", "Message")
                        yield table
                    with Vertical(classes="logs-pane"):
                        yield Static(
                            "Selected log record",
                            id="logs-detail-title",
                            classes="logs-pane-title",
                        )
                        yield RichLog(id="logs-output", wrap=True, markup=True)
        yield Footer()

    async def on_mount(self) -> None:
        await self.refresh_all()
        self.set_interval(1.0, self.refresh_status)

    async def _request(self, command: str, **payload: Any) -> dict[str, Any]:
        request = {"command": command, **payload}
        response = await asyncio.to_thread(control_request, self.socket_path, request)
        if response.get("ok") is False:
            raise RuntimeError(str(response.get("error", "Caretaker control request failed")))
        return response

    async def refresh_status(self) -> None:
        try:
            status = await self._request("status")
        except Exception as exc:
            self.query_one("#operator-status", Static).update(
                f"DISCONNECTED | {type(exc).__name__}: {exc}"
            )
            return
        self._last_status = status
        runtime = status.get("runtime") or {}
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
        line = (
            f"Status {runtime.get('current_status', 'STARTING')}  |  "
            f"Alert {runtime.get('alert_level', 'NONE')}  |  "
            f"Incidents {runtime.get('active_incident_count', 0)}  |  "
            f"Validating {runtime.get('validation_count', 0)}  |  "
            f"Approvals {runtime.get('pending_approval_count', 0)}  |  "
            f"Targets {runtime.get('target_count', 0)}  |  "
            f"Worker issues {len(unhealthy)}"
        )
        self.query_one("#operator-status", Static).update(line)
        details = [
            f"Application PID: {status.get('application_pid')}   running={status.get('application_running')}",
            f"Active incident targets: {', '.join(incident_targets) if incident_targets else 'none'}",
            f"Validating functions: {', '.join(validating) if validating else 'none'}",
            f"Degraded capabilities: {', '.join(degraded) if degraded else 'none'}",
        ]
        self.query_one("#overview-details", Static).update("\n".join(details))

    async def refresh_targets(self) -> None:
        response = await self._request("runtime-targets")
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        for target in response.get("targets", []):
            target_id = str(target.get("target_id", ""))
            table.add_row(
                target_id,
                str(target.get("repair_mode") or "-"),
                str(target.get("repair_authority") or "-"),
                str(target.get("function_version") if target.get("function_version") is not None else "-"),
                "yes" if target.get("guard_enabled") else "no",
                "repairing" if target.get("repair_in_progress") else "ready",
                key=target_id,
            )

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "logs-table":
            row = event.data_table.get_row(event.row_key)
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._log_records[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            self.query_one("#logs-detail-title", Static).update(
                f"Log record {record_number} | "
                f"{record.get('channel', '-')} | {record.get('target_id') or 'no target'}"
            )
            self._write_json("#logs-output", record)
            return

        if event.data_table.id != "targets-table":
            return
        row = event.data_table.get_row(event.row_key)
        if not row:
            return
        target_id = str(row[0])
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
        await self.refresh_status()
        try:
            await self.refresh_targets()
        except Exception as exc:
            self.query_one("#overview-details", Static).update(
                f"Unable to read runtime targets: {type(exc).__name__}: {exc}"
            )

    async def action_refresh(self) -> None:
        await self.refresh_all()

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

    async def refresh_logs(self) -> None:
        response = await self._request("logs", limit=200)
        records = response.get("records", [])
        self._log_records = [dict(record) for record in records if isinstance(record, dict)]

        table = self.query_one("#logs-table", DataTable)
        table.clear()
        for index in range(len(self._log_records) - 1, -1, -1):
            record = self._log_records[index]
            occurred_at = str(record.get("occurred_at") or "")
            timestamp = occurred_at[:19].replace("T", " ") if occurred_at else "-"
            table.add_row(
                index + 1,
                timestamp,
                self._log_level(record.get("severity")),
                self._compact_log_text(record.get("channel"), limit=18) or "-",
                self._compact_log_text(record.get("target_id"), limit=28) or "-",
                self._compact_log_text(record.get("message"), limit=80) or "-",
            )

        detail = self.query_one("#logs-output", RichLog)
        detail.clear()
        self.query_one("#logs-detail-title", Static).update("Selected log record")
        if self._log_records:
            detail.write("Select a log record from the list to inspect its full JSON.")
        else:
            detail.write("No log records were returned.")

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
            if button == "repair-events":
                target = self.query_one("#repair-target", Input).value.strip() or None
                response = await self._request("runtime-repair-events", target=target, limit=100)
                self._write_json("#repair-output", response)
                return
            if button == "repair-approvals":
                response = await self._request("runtime-repair-approvals")
                self._write_json("#repair-output", response)
                return
            if button in {"repair-approve", "repair-reject"}:
                episode = self.query_one("#repair-episode", Input).value.strip()
                if not episode:
                    raise ValueError("Enter an episode UUID")
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
            if button == "logs-refresh":
                await self.refresh_logs()
        except Exception as exc:
            output = "#guard-output" if button.startswith("guard-") else "#repair-output"
            if button == "investigate-run":
                output = "#investigate-output"
            elif button == "logs-refresh":
                output = "#logs-output"
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
    try:
        socket_path = args.socket.expanduser().resolve() if args.socket else discover_control_socket(args.data_directory.expanduser().resolve())
    except (FileNotFoundError, RuntimeError) as exc:
        parser.error(str(exc))
        return 2
    CaretakerConsoleApp(socket_path).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
