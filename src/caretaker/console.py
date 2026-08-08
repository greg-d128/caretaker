from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, Label, RichLog, Static, TabbedContent, TabPane

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
        height: 5;
        padding: 1 2;
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

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Connecting to Caretaker...", id="operator-status")
        with TabbedContent(initial="overview"):
            with TabPane("Overview", id="overview"):
                yield Static("", id="overview-details")
                table = DataTable(id="targets-table", cursor_type="row")
                table.add_columns(
                    "Target", "Mode", "Authority", "Version", "Guard", "Slot state"
                )
                yield table
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
                with Horizontal(classes="toolbar"):
                    yield Button("Refresh logs", id="logs-refresh")
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
            f"Validating functions: {', '.join(validating) if validating else 'none'}",
            f"Degraded capabilities: {', '.join(degraded) if degraded else 'none'}",
        ]
        self.query_one("#overview-details", Static).update("\n".join(details))

    async def refresh_targets(self) -> None:
        response = await self._request("runtime-targets")
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        for target in response.get("targets", []):
            table.add_row(
                str(target.get("target_id", "")),
                str(target.get("repair_mode") or "-"),
                str(target.get("repair_authority") or "-"),
                str(target.get("function_version") if target.get("function_version") is not None else "-"),
                "yes" if target.get("guard_enabled") else "no",
                "repairing" if target.get("repair_in_progress") else "ready",
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
                response = await self._request("logs", limit=200)
                self._write_json("#logs-output", response.get("records", []))
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
