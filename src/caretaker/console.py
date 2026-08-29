from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.syntax import Syntax
from rich.text import Text
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
from textual.widgets.data_table import RowDoesNotExist

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
    #data-status, #operator-context {
        height: 3;
        padding: 0 2;
        color: $text-muted;
        border-bottom: solid $surface-lighten-2;
    }
    #operator-context { layout: horizontal; }
    #operator-context-label { width: 1fr; }
    #context-clear, #save-report, #save-capsule-view { width: auto; min-width: 14; margin-left: 1; }
    #attention-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 3fr 2fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .attention-pane {
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
    }
    #attention-actions { height: 4; padding: 0 1; align-vertical: middle; }
    #attention-actions Button { width: auto; min-width: 16; margin-left: 1; }
    #incident-capsule-help, #incident-capsule-status {
        height: auto;
        padding: 0 2;
        color: $text-muted;
    }
    #incident-capsule-toolbar {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #incident-capsule-filter { width: 1fr; }
    #incident-capsule-toolbar Button { width: auto; min-width: 12; margin-left: 1; }
    #incident-capsule-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 3fr 2fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .incident-capsule-pane {
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
    }
    #incident-capsule-output { height: 1fr; }
    #incident-capsule-revision-actions {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #incident-capsule-revision-actions Input { width: 1fr; }
    #incident-capsule-revision-actions Button { width: auto; min-width: 14; margin-left: 1; }
    #incident-artifact-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-top: solid $surface-lighten-2;
    }
    #incident-artifact-table { height: 10; }
    #incident-timeline-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-top: solid $surface-lighten-2;
    }
    #incident-timeline-table { height: 10; }
    #incident-capsule-detail-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $surface-lighten-2;
    }
    #overview-details {
        height: 6;
        padding: 1 2;
    }
    #target-details {
        height: 12;
        border-top: solid $surface-lighten-2;
    }
    #overview-help, #guard-help, #overview-status-legend {
        height: auto;
        padding: 0 2;
        color: $text-muted;
    }
    #overview-actions, #guard-context-actions, #guard-filter-row {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #overview-actions Button, #guard-context-actions Button, #guard-filter-row Button {
        width: auto;
        min-width: 14;
        margin-left: 1;
    }
    #guard-filter { width: 1fr; }
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
    #targets-filter-row, #logs-filter-row {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #targets-filter-row Input, #logs-filter-row Input { width: 1fr; }
    #targets-filter-row Button, #logs-filter-row Button {
        width: auto;
        min-width: 12;
        margin-left: 1;
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
    #logs-actions, #guard-actions, #investigate-actions {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #logs-actions Button, #guard-actions Button, #investigate-actions Button {
        width: auto;
        min-width: 14;
        margin-right: 1;
    }
    #guard-split, #investigate-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 3fr 2fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .guard-pane, .investigate-pane {
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
        overflow: hidden hidden;
    }
    .context-pane-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $surface-lighten-2;
    }
    #guard-table, #guard-output, #investigate-table, #investigate-output {
        height: 1fr;
        min-height: 0;
        border: none;
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
    #repair-toolbar { height: 4; padding: 0 1; align-vertical: middle; }
    #repair-filter { width: 1fr; }
    #repair-context-actions { height: 4; padding: 0 1; align-vertical: middle; }
    #repair-context-actions Button { width: auto; min-width: 14; margin-left: 1; }
    #repair-reason {
        width: 1fr;
        min-width: 24;
    }
    #repair-actions Button {
        width: auto;
        min-width: 12;
        margin-left: 1;
    }

    #behavior-toolbar, #behavior-compare-actions, #behavior-manage-actions {
        height: 4;
        padding: 0 1;
        align-vertical: middle;
    }
    #behavior-filter-row { height: 4; padding: 0 1; align-vertical: middle; }
    #behavior-filter { width: 1fr; }
    #behavior-filter-row Button { width: auto; min-width: 14; margin-left: 1; }
    #behavior-selection-status {
        height: 3;
        padding: 0 2;
        color: $text-muted;
    }
    #behavior-subject { width: 1fr; min-width: 24; }
    #behavior-model { width: 1fr; min-width: 18; }
    #behavior-archive-reason { width: 1fr; min-width: 18; }
    #behavior-manage-confirm { width: auto; }
    #behavior-toolbar Button, #behavior-compare-actions Button, #behavior-manage-actions Button {
        width: auto;
        min-width: 12;
        margin-left: 1;
    }
    #behavior-split {
        height: 1fr;
        min-height: 0;
        grid-size: 2 1;
        grid-columns: 3fr 2fr;
        grid-rows: 1fr;
        grid-gutter: 1;
    }
    .behavior-pane {
        height: 1fr;
        min-height: 0;
        border: solid $surface-lighten-2;
        overflow: hidden hidden;
    }
    .behavior-pane-title {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $surface-lighten-2;
    }
    #behavior-table, #behavior-output {
        height: 1fr;
        min-height: 0;
        border: none;
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
    #policy-presets { height: 4; padding: 0 1; align-vertical: middle; }
    #policy-presets Button { width: auto; min-width: 16; margin-left: 1; }
    #policy-preview-output { height: 5; padding: 1 2; border: solid $surface-lighten-2; }
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
        self._displayed_repair_records: list[dict[str, Any]] = []
        self._selected_repair_approval: str | None = None
        self._selected_repair_record: dict[str, Any] | None = None
        self._repair_source_view = False
        self._authority_snapshot: dict[str, Any] = {}
        self._authority_rows: list[dict[str, Any]] = []
        self._selected_authority_lease: str | None = None
        self._policy_preview: dict[str, Any] | None = None
        self._behavior_records: list[dict[str, Any]] = []
        self._displayed_behavior_records: list[dict[str, Any]] = []
        self._behavior_collection_id: str | None = None
        self._behavior_loaded_revision: int | None = None
        self._selected_behavior_snapshot: str | None = None
        self._behavior_references: dict[str, str] = {}
        self._behavior_last_comparison: dict[str, Any] | None = None
        self._behavior_view_mode = "detail"
        self._guard_records: list[dict[str, Any]] = []
        self._selected_guard_target: str | None = None
        self._investigation_records: list[dict[str, Any]] = []
        self._selected_investigation_record: dict[str, Any] | None = None
        self._selected_log_record: dict[str, Any] | None = None
        self._capsule_records: list[dict[str, Any]] = []
        self._selected_capsule: dict[str, Any] | None = None
        self._incident_artifact_records: list[dict[str, Any]] = []
        self._incident_timeline_records: list[dict[str, Any]] = []
        self._selected_target: str | None = None
        self._attention_records: list[dict[str, Any]] = []
        self._selected_attention_record: dict[str, Any] | None = None
        self._context_target: str | None = None
        self._context_incident: str | None = None
        self._context_call: str | None = None
        self._logs_source = "not loaded"
        self._authority_source = "not loaded"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Connecting to Caretaker...", id="operator-status")
        yield Static("Data has not been refreshed yet", id="data-status")
        with Horizontal(id="operator-context"):
            yield Static(
                "Context: all targets and incidents | Select an item to focus related views",
                id="operator-context-label",
            )
            yield Button("Clear context", id="context-clear", disabled=True)
            yield Button("Save Report", id="save-report", variant="primary")
            yield Button("Save view to capsule", id="save-capsule-view", disabled=True)
        with TabbedContent(initial="attention"):
            with TabPane("Attention", id="attention"):
                yield Static(
                    "Start here. This queue combines active incidents, Guard findings, failed Repairs, "
                    "pending approvals, policy violations, and degraded runtime components.",
                    classes="context-pane-title",
                )
                with Grid(id="attention-split"):
                    with Vertical(classes="attention-pane"):
                        yield Static("Items requiring operator attention", id="attention-list-title", classes="context-pane-title")
                        table = DataTable(id="attention-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Priority", "Kind", "Target", "Time", "Summary")
                        yield table
                    with Vertical(classes="attention-pane"):
                        yield Static("Select an item to see why it matters", id="attention-detail-title", classes="context-pane-title")
                        yield RichLog(id="attention-output", wrap=True, markup=True)
                        with Horizontal(id="attention-actions"):
                            yield Button("Open related view", id="attention-open", disabled=True, variant="primary")
                            yield Button("Investigate evidence", id="attention-investigate", disabled=True)
            with TabPane("Incident Explorer", id="incidents"):
                yield Static(
                    "Browse immutable Incident Capsule revisions and their verified side artifacts. "
                    "Selection and inspection are read-only; integrity failures remain visible and are never treated as valid evidence.",
                    id="incident-capsule-help",
                )
                with Horizontal(id="incident-capsule-toolbar"):
                    yield Input(
                        placeholder="Filter capsules: incident UUID, target, trigger, integrity:invalid",
                        id="incident-capsule-filter",
                    )
                    yield Button("Refresh", id="incident-capsule-refresh", variant="primary")
                yield Static("Incident Capsules not loaded", id="incident-capsule-status")
                with Grid(id="incident-capsule-split"):
                    with Vertical(classes="incident-capsule-pane"):
                        yield Static("Incident Capsules", classes="context-pane-title")
                        table = DataTable(id="incident-capsule-table")
                        table.cursor_type = "row"
                        table.add_columns(
                            "#", "Incident", "Revision", "Created", "Artifacts", "Comms", "Integrity"
                        )
                        yield table
                    with Vertical(classes="incident-capsule-pane"):
                        yield Static("Select an Incident Capsule", id="incident-capsule-detail-title")
                        with Horizontal(id="incident-capsule-revision-actions"):
                            yield Input(placeholder="Revision (blank = latest)", id="incident-capsule-revision")
                            yield Button("Load revision", id="incident-capsule-load", disabled=True)
                        yield RichLog(id="incident-capsule-output", wrap=False, markup=True)
                        yield Static("Side artifacts", id="incident-artifact-title")
                        table = DataTable(id="incident-artifact-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Kind", "Created", "Source", "Content hash")
                        yield table
                        yield Static("Correlated persisted timeline", id="incident-timeline-title")
                        table = DataTable(id="incident-timeline-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Time", "Level", "Channel", "Target", "Message")
                        yield table
            with TabPane("Overview", id="overview"):
                yield Static(
                    "Registered functions and their operational state. Problem states are listed first; "
                    "select a target for plain-language status and related evidence shortcuts.",
                    id="overview-help",
                )
                yield Static("", id="overview-details")
                with Horizontal(id="targets-filter-row"):
                    yield Input(
                        placeholder=(
                            "Filter targets: text, status:validating, mode:automatic, "
                            "authority:approval, role:target, level:behavior, guard:yes"
                        ),
                        id="targets-filter",
                    )
                    yield Button("Clear filter", id="targets-filter-clear")
                table = DataTable(id="targets-table")
                table.cursor_type = "row"
                table.add_columns(
                    "Target", "Health", "Needs attention", "Repair mode", "Repair approval",
                    "Slot role", "Adaptive observation", "Active version", "Runtime monitoring"
                )
                yield table
                yield Static(
                    "READY = registered/no active issue; LEARNING = insufficient observations; "
                    "VALIDATING = candidate under observation; QUARANTINED/REPAIRING/DEVIATION require review.",
                    id="overview-status-legend",
                )
                with Horizontal(id="overview-actions"):
                    yield Button("Guard evidence", id="overview-guard", disabled=True)
                    yield Button("Behavior history", id="overview-behavior", disabled=True)
                    yield Button("Related logs", id="overview-logs", disabled=True)
                    yield Button("Investigate target", id="overview-investigate", disabled=True, variant="primary")
                yield RichLog(id="target-details", wrap=True, markup=True)
            with TabPane("Guard", id="guard"):
                yield Static(
                    "Guard shows observed runtime behavior and departures from accepted expectations. "
                    "Select a target before using evidence actions.",
                    id="guard-help",
                )
                with Horizontal(id="guard-actions"):
                    yield Button("Refresh", id="guard-refresh", variant="primary")
                    yield Button("Behavior summary", id="guard-summary", disabled=True)
                    yield Button("Observed activity", id="guard-events", disabled=True)
                    yield Button("Deviations", id="guard-deviations", disabled=True)
                    yield Button("Code inspections", id="guard-inspections", disabled=True)
                    yield Checkbox("I reviewed baseline evidence", id="guard-baseline-confirm", disabled=True)
                    yield Button("Accept as expected", id="guard-baseline", disabled=True)
                    yield Button("Analyze with local AI", id="guard-assess", disabled=True)
                with Horizontal(id="guard-filter-row"):
                    yield Input(placeholder="Filter Guard targets or states", id="guard-filter")
                    yield Button("Clear filter", id="guard-filter-clear")
                with Grid(id="guard-split"):
                    with Vertical(classes="guard-pane"):
                        yield Static("Guard operational status", classes="context-pane-title")
                        table = DataTable(id="guard-table")
                        table.cursor_type = "row"
                        table.add_columns("Target", "Guard state", "Severity", "Last evidence", "Findings", "Escalations")
                        yield table
                    with Vertical(classes="guard-pane"):
                        yield Static("Select a Guard target", id="guard-detail-title", classes="context-pane-title")
                        yield RichLog(id="guard-output", wrap=True, markup=True)
                with Horizontal(id="guard-context-actions"):
                    yield Button("Behavior history", id="guard-open-behavior", disabled=True)
                    yield Button("Related logs", id="guard-open-logs", disabled=True)
                    yield Button("Investigate findings", id="guard-open-investigate", disabled=True, variant="primary")
            with TabPane("Behavior", id="behavior"):
                yield Static(
                    "One row is the best analytical snapshot for each subject/generation, sorted by subject then newest generation. "
                    "Generation is a fingerprint of code and monitoring semantics—not a signature. "
                    "First/last seen and recent hourly call activity keep rare generations visible. "
                    "Snapshots are evidence, not accuracy guarantees. Ordinary coverage is cumulative across "
                    "verified disjoint epochs; partial marks one non-cumulative capture. "
                    "a code or monitoring change starts a new generation but earlier generations remain comparable. "
                    "The newest generation is the default green reference for each subject; select another row to compare.",
                    id="behavior-help",
                )
                with Horizontal(id="behavior-toolbar"):
                    yield Input(
                        placeholder="Target id for function capture, or module name for module capture",
                        id="behavior-subject",
                    )
                    yield Button("Save current function sample", id="behavior-capture-function", variant="primary")
                    yield Button("Save current module sample", id="behavior-capture-module", variant="primary")
                    yield Button("Refresh", id="behavior-refresh")
                with Horizontal(id="behavior-filter-row"):
                    yield Input(
                        placeholder="Filter snapshots: subject text, evidence:preliminary, integrity:invalid, generation:hash",
                        id="behavior-filter",
                    )
                    yield Button("Clear filter", id="behavior-filter-clear")
                    yield Checkbox("Show zero-call evidence", id="behavior-show-zero-calls")
                    yield Checkbox("Show older generations", id="behavior-show-older")
                with Grid(id="behavior-split"):
                    with Vertical(classes="behavior-pane"):
                        yield Static("Behavior generations", id="behavior-list-title", classes="behavior-pane-title")
                        table = DataTable(id="behavior-table")
                        table.cursor_type = "row"
                        table.add_columns(
                            "#", "Role", "Subject", "Generation", "First seen", "Last seen",
                            "Collected calls", "Recent activity", "Evidence", "Integrity",
                        )
                        yield table
                    with Vertical(classes="behavior-pane"):
                        yield Static("Selected generation / comparison", id="behavior-detail-title", classes="behavior-pane-title")
                        yield RichLog(id="behavior-output", wrap=True, markup=True)
                yield Static(
                    "Select a generation. Set Reference changes that subject's green reference; Compare epochs compares each row's representative sealed epoch and also reports cumulative generation coverage. Archiving removes every active snapshot in the selected generation and records your reason.",
                    id="behavior-selection-status",
                )
                with Horizontal(id="behavior-compare-actions"):
                    yield Input(placeholder="Local AI model name (Ollama)", id="behavior-model")
                    yield Button("Set Reference", id="behavior-set-reference", disabled=True)
                    yield Button("Compare with reference", id="behavior-compare", disabled=True, variant="primary")
                    yield Button("Explain with local AI", id="behavior-assess-comparison", disabled=True)
                with Horizontal(id="behavior-manage-actions"):
                    yield Button("AI history analysis", id="behavior-assess-history")
                    yield Input(
                        placeholder="Reason for archiving this generation",
                        id="behavior-archive-reason",
                        max_length=500,
                    )
                    yield Checkbox("Confirm archive generation", id="behavior-manage-confirm", disabled=True)
                    yield Button("Archive generation", id="behavior-archive", variant="warning", disabled=True)

            with TabPane("Repair", id="repair"):
                yield Static(
                    "Repair groups incidents, candidate work, validation outcomes, and operator decisions by episode. "
                    "WAITING items require explicit review; historical events are read-only.",
                    id="repair-help",
                )
                with Horizontal(id="repair-toolbar"):
                    yield Button("Refresh", id="repair-refresh")
                    yield Input(placeholder="Filter by target, state, episode, or description", id="repair-filter")
                with Grid(id="repair-split"):
                    with Vertical(classes="repair-pane"):
                        yield Static(
                            "Recent and waiting Repair activity",
                            id="repair-list-title",
                            classes="repair-pane-title",
                        )
                        table = DataTable(id="repair-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "State", "Time", "Target", "Description", "Repair case")
                        yield table
                    with Vertical(classes="repair-pane"):
                        yield Static(
                            "Selected Repair record",
                            id="repair-detail-title",
                            classes="repair-pane-title",
                        )
                        yield RichLog(id="repair-output", wrap=False, markup=True)
                        with Horizontal(id="repair-actions"):
                            yield Checkbox("I reviewed evidence and confirm this decision", id="repair-approve-confirm", disabled=True)
                            yield Input(
                                placeholder="Rejection reason (used only for Reject)",
                                id="repair-reason",
                            )
                            yield Button(
                                "View proposed code",
                                id="repair-source",
                                disabled=True,
                            )
                            yield Button("Activate replacement", id="repair-approve", variant="success", disabled=True)
                            yield Button("Reject replacement", id="repair-reject", variant="error", disabled=True)
                        with Horizontal(id="repair-context-actions"):
                            yield Button("Triggering logs", id="repair-open-logs", disabled=True)
                            yield Button("Guard evidence", id="repair-open-guard", disabled=True)
                            yield Button("Investigate episode", id="repair-open-investigate", disabled=True, variant="primary")
            with TabPane("Policy", id="policy"):
                yield Static(
                    "Review assurance and violations first. Runtime leases are temporary audited changes; "
                    "use a preset or preview an advanced setting before applying it.",
                    id="policy-help",
                )
                yield Static("Authority policy state unavailable", id="policy-summary")
                with Grid(id="policy-split"):
                    with Vertical(classes="policy-pane"):
                        yield Static("Policy sources and temporary changes", classes="policy-pane-title")
                        table = DataTable(id="policy-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Source", "Authority", "Signature", "Assurance status", "Violations")
                        yield table
                    with Vertical(classes="policy-pane"):
                        yield Static("Selected policy authority record", id="policy-detail-title", classes="policy-pane-title")
                        yield RichLog(id="policy-output", wrap=True, markup=True)
                with Horizontal(id="policy-lease-row-1"):
                    yield Input(placeholder="Target id / glob (required for repair.*)", id="policy-target")
                    yield Input(placeholder="Policy path, e.g. repair.authority", id="policy-path")
                    yield Input(placeholder='Value as JSON or text, e.g. "AUTOMATIC_ELIGIBLE_REPAIRS"', id="policy-value")
                with Horizontal(id="policy-presets"):
                    yield Button("Preset: require approval", id="policy-preset-approval")
                    yield Button("Preset: automatic eligible repair", id="policy-preset-automatic")
                    yield Button("Preview change", id="policy-preview", variant="primary")
                    yield Checkbox("I reviewed scope and guarantee impact", id="policy-confirm", disabled=True)
                yield Static("No policy change previewed", id="policy-preview-output")
                with Horizontal(id="policy-lease-row-2"):
                    yield Input(value="3600", placeholder="Seconds", id="policy-duration")
                    yield Input(placeholder="Incident reason / operator justification", id="policy-reason")
                    yield Checkbox("Allow constraint override", id="policy-override")
                    yield Button("Apply previewed lease", id="policy-apply", variant="warning", disabled=True)
                    yield Checkbox("Confirm release", id="policy-release-confirm", disabled=True)
                    yield Button("End temporary change", id="policy-release", disabled=True)
                    yield Button("Refresh", id="policy-refresh")
                with Horizontal(id="policy-signed-row"):
                    yield Input(
                        placeholder="Signed policy-change file under policy/runtime-leases/",
                        id="policy-signed-descriptor",
                    )
                    yield Checkbox("I reviewed signed scope", id="policy-signed-confirm", disabled=True)
                    yield Button("Apply signed lease", id="policy-apply-signed", variant="primary", disabled=True)
            with TabPane("Investigate", id="investigate"):
                with Horizontal(classes="toolbar"):
                    yield Input(placeholder="Target id (optional)", id="investigate-target")
                    yield Input(placeholder="Incident UUID (optional)", id="investigate-incident")
                    yield Input(placeholder="Call UUID (optional)", id="investigate-call")
                    yield Input(value="15", placeholder="Minutes", id="investigate-minutes")
                    yield Input(placeholder="Local AI model (blank = built-in analysis)", id="investigate-model")
                    yield Button("Build investigation report", id="investigate-run", variant="primary")
                with Horizontal(classes="toolbar"):
                    yield Input(
                        value="Investigate the current Caretaker incident",
                        placeholder="Investigation objective",
                        id="investigate-objective",
                    )
                yield Static(
                    "Leave the model blank for built-in analysis without AI. Entering a model explicitly "
                    "sends the bounded evidence bundle to the configured local Ollama endpoint.",
                    id="investigate-help",
                )
                yield Static("Scope: last 15 minutes, all available evidence", id="investigate-scope")
                with Grid(id="investigate-split"):
                    with Vertical(classes="investigate-pane"):
                        yield Static("Recent warnings and unusual activity", classes="context-pane-title")
                        table = DataTable(id="investigate-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Time", "Level", "Channel", "Target", "Description")
                        yield table
                    with Vertical(classes="investigate-pane"):
                        yield Static("Select an item or investigate the current period", id="investigate-detail-title", classes="context-pane-title")
                        yield RichLog(id="investigate-output", wrap=True, markup=True)
            with TabPane("Logs", id="logs"):
                yield Static(
                    "Showing a bounded evidence window. Correlated investigation uses target/channel/logger identifiers; "
                    "it is not semantic similarity. Select a record to expose navigation.",
                    id="logs-help",
                )
                yield Static("Logs not loaded", id="logs-source-status")
                with Grid(id="logs-split"):
                    with Vertical(classes="logs-pane"):
                        with Horizontal(id="logs-filter-row"):
                            yield Input(
                                placeholder=(
                                    "Filter logs: text, level:warn+, channel:guard, "
                                    "target:lab.divide, logger:name"
                                ),
                                id="logs-filter",
                            )
                            yield Button("Clear filter", id="logs-filter-clear")
                        table = DataTable(id="logs-table")
                        table.cursor_type = "row"
                        table.add_columns("#", "Time", "Level", "Channel", "Target", "Message")
                        yield table
                        with Horizontal(id="logs-actions"):
                            yield Button("Investigate related events", id="logs-investigate", disabled=True, variant="primary")
                            yield Button("Open related tab", id="logs-related", disabled=True)
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
        timeout = 360.0 if command in {
            "investigate",
            "behavior-assess",
            "behavior-assess-history",
        } else 30.0 if command == "behavior-list" else 5.0
        response = await asyncio.to_thread(
            control_request, self.socket_path, request, timeout=timeout
        )
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
        release_integrity = (self._last_status or {}).get("release_integrity") or {}
        release_status = str(release_integrity.get("status") or "NOT_CONFIGURED")
        self.query_one("#operator-status", Static).update(
            f"Status {status_label}  |  "
            f"Last alert {self._metric(runtime, 'alert_level')}  |  "
            f"Last incidents {self._metric(runtime, 'active_incident_count')}  |  "
            f"Last validating {self._metric(runtime, 'validation_count')}  |  "
            f"Last approvals {self._metric(runtime, 'pending_approval_count')}  |  "
            f"Policy {assurance}  |  Violations {violations}  |  Release integrity {release_status}"
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
        except Exception as exc:
            self._application_running = False
            message = str(exc).strip()
            reason = f"{type(exc).__name__}: {message}" if message else type(exc).__name__
            self._offline_overview(
                reason=f"Caretaker supervisor control socket is unavailable: {reason}"
            )
            return

        self._last_status = status
        behavior_collection_id = str(status.get("behavior_collection_id") or "")
        behavior_revision = int(status.get("behavior_revision") or 0)
        if (
            (
                behavior_collection_id != (self._behavior_collection_id or "")
                or behavior_revision != self._behavior_loaded_revision
            )
            and self.query_one(TabbedContent).active == "behavior"
        ):
            try:
                await self.refresh_behavior()
            except Exception as exc:
                self.query_one("#behavior-list-title", Static).update(
                    f"Behavior auto-refresh delayed: {type(exc).__name__}: {exc}. "
                    "Existing data remains visible; Caretaker will retry."
                )
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
        validation_backends = sorted(
            {
                f"{item.get('validation_backend', 'unknown')}:{item.get('validation_isolation', 'unknown')}"
                for item in runtime.get("active_validations") or []
            }
        )
        incidents = runtime.get("active_incidents") or []
        incident_targets = sorted(
            {str(item.get("target_id")) for item in incidents if item.get("target_id")}
        )
        degraded = runtime.get("degraded_components") or []
        authority_summary = status.get("authority_policy") or {}
        release_integrity = status.get("release_integrity") or {}
        release_integrity_status = str(release_integrity.get("status") or "NOT_CONFIGURED")
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
            f"Release integrity {release_integrity_status}  |  "
            f"Worker issues {len(unhealthy)}"
        )
        self.query_one("#operator-status", Static).update(line)
        details = [
            f"Application PID: {status.get('application_pid')}   running=True",
            f"Active incident targets: {', '.join(incident_targets) if incident_targets else 'none'}",
            f"Validating functions: {', '.join(validating) if validating else 'none'}",
            f"Validation backends: {', '.join(validation_backends) if validation_backends else 'none'}",
            f"Degraded capabilities: {', '.join(degraded) if degraded else 'none'}",
            f"Release integrity: {release_integrity_status}",
            "Release root externally anchored: "
            + ("yes" if release_integrity.get("root_anchored") is True else "no / not checked"),
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
            "role": str(target.get("slot_role") or "").casefold(),
            "level": str(target.get("observation_level") or "").casefold(),
            "lifecycle": " ".join((
                str(target.get("lifecycle_stage") or ""),
                str(target.get("lifecycle_label") or ""),
            )).casefold(),
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
                fields["role"],
                fields["level"],
                fields["lifecycle"],
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
        self._displayed_target_records.sort(
            key=lambda target: (
                0 if self._target_attention_reason(target) != "none" else 1,
                str(target.get("target_id") or ""),
            )
        )
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        for target in self._displayed_target_records:
            target_id = str(target.get("target_id", ""))
            table.add_row(
                target_id,
                str(target.get("status") or "READY"),
                self._target_attention_reason(target),
                str(target.get("repair_mode") or "-"),
                str(target.get("repair_authority") or "-"),
                self._slot_role_display(target.get("slot_role")),
                self._observation_display(
                    target.get("observation_level"), target.get("slot_role")
                ),
                str(
                    target.get("function_version")
                    if target.get("function_version") is not None
                    else "-"
                ),
                "yes" if target.get("guard_enabled") else "no",
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

    @classmethod
    def _slot_role_display(cls, value: Any) -> str:
        role = cls._enum_name(value)
        return {
            "TARGET_IMPLEMENTATION": "target",
            "OUTPUT_VALIDATOR": "validator",
            "OUTPUT_COMPARATOR": "comparator",
            "SNAPSHOTTER": "snapshotter",
            "RESTORER": "restorer",
            "DEPENDENCY_BOUNDARY": "dependency",
        }.get(role, role.casefold().replace("_", " ") if role else "-")

    @classmethod
    def _observation_display(cls, value: Any, slot_role: Any = None) -> str:
        level = cls._enum_name(value)
        if level == "LIGHTWEIGHT":
            return "normal"
        if level in {"BEHAVIOR", "REPAIR"}:
            return f"escalated: {level.casefold()}"
        if level:
            return level.casefold()
        return "not adaptive" if cls._enum_name(slot_role) else "-"

    def _target_attention_reason(self, target: dict[str, Any]) -> str:
        target_id = str(target.get("target_id") or "")
        status = str(target.get("status") or "READY").upper()
        if status in {"REPAIRING", "QUARANTINED", "FAILED", "VALIDATING"}:
            return status.lower()
        observation_level = self._enum_name(target.get("observation_level"))
        if observation_level == "REPAIR":
            return "repair escalation"
        if observation_level == "BEHAVIOR":
            return "behavior escalation"
        guard = next(
            (item for item in self._guard_records if str(item.get("target_id") or "") == target_id),
            None,
        )
        if guard and int(guard.get("violation_count") or 0) > 0:
            return f"{guard.get('violation_count')} Guard finding(s)"
        if any(
            str(item.get("target_id") or "") == target_id
            and item.get("state") in {"WAITING", "FAILED", "ROLLBACK", "BLOCKED", "ERROR"}
            for item in self._repair_records
        ):
            return "Repair review"
        return "none"

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
        for target in self._target_records:
            if not target.get("target_id"):
                target["slot_state"] = ""
                target["candidate_state"] = ""
                target["status"] = self._target_status(target)
                continue
            try:
                state_result = await self._request(
                    "runtime-target-state",
                    target=str(target["target_id"]),
                )
            except Exception:
                slot_state, candidate_state = "", ""
            else:
                slot_state, candidate_state = self._target_runtime_states(state_result)
            target["slot_state"] = slot_state
            target["candidate_state"] = candidate_state
            target["status"] = self._target_status(target)
        self._apply_target_filter()

    @staticmethod
    def _subject_target(value: Any) -> str:
        if not isinstance(value, dict):
            return ""
        subject = value.get("subject")
        if isinstance(subject, dict):
            return str(subject.get("target_id") or "")
        return str(value.get("target_id") or "")

    @staticmethod
    def _latest_evidence_time(*groups: Any) -> str:
        values = []
        for group in groups:
            if not isinstance(group, (list, tuple)):
                continue
            for item in group:
                if isinstance(item, dict) and item.get("created_at"):
                    values.append(str(item["created_at"]))
        if not values:
            return "never"
        return max(values).replace("T", " ").replace("+00:00", "Z")[:19]

    async def refresh_guard(self) -> None:
        targets = [
            target for target in self._target_records
            if target.get("guard_enabled") and target.get("target_id")
        ]
        records: list[dict[str, Any]] = []
        decisions: list[dict[str, Any]] = []
        if self._application_running:
            try:
                response = await self._request("runtime-guard-decisions", limit=200)
                decisions = [dict(item) for item in response.get("decisions", ()) if isinstance(item, dict)]
            except Exception:
                decisions = []
            responses = []
            for target in targets:
                responses.append(
                    await asyncio.gather(
                        self._request("runtime-guard-summary", target=str(target["target_id"])),
                        self._request("runtime-guard-deviations", target=str(target["target_id"]), limit=100),
                        self._request("runtime-guard-inspections", target=str(target["target_id"]), limit=100),
                        return_exceptions=True,
                    )
                )
        else:
            responses = [()] * len(targets)

        for target, response_group in zip(targets, responses):
            target_id = str(target["target_id"])
            summary_response = response_group[0] if len(response_group) > 0 else {}
            deviations_response = response_group[1] if len(response_group) > 1 else {}
            inspections_response = response_group[2] if len(response_group) > 2 else {}
            summary = summary_response.get("summary") if isinstance(summary_response, dict) else None
            deviations = deviations_response.get("deviations", ()) if isinstance(deviations_response, dict) else ()
            inspections = inspections_response.get("inspections", ()) if isinstance(inspections_response, dict) else ()
            target_decisions = [item for item in decisions if self._subject_target(item) == target_id]
            records.append({
                "target_id": target_id,
                "status": self._guard_state(summary, deviations, inspections),
                "severity": self._guard_severity(deviations),
                "last_check": self._latest_evidence_time(inspections, deviations),
                "violation_count": len(deviations),
                "escalation_count": len(target_decisions),
                "summary": summary,
                "deviations": deviations,
                "inspections": inspections,
                "decisions": target_decisions,
            })
        self._guard_records = records
        self._apply_guard_filter()
        self._apply_target_filter()

    @staticmethod
    def _guard_severity(deviations: Any) -> str:
        ranks = {"CRITICAL": 4, "HIGH": 3, "ERROR": 3, "WARNING": 2, "WARN": 2, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        best = "NONE"
        best_rank = -1
        for item in deviations or ():
            if not isinstance(item, dict):
                continue
            value = str(item.get("severity") or "").upper()
            if not value:
                try:
                    score = float(item.get("significance_score") or 0)
                except (TypeError, ValueError):
                    score = 0
                value = "HIGH" if score >= 80 else "WARNING" if score >= 60 else "LOW"
            rank = ranks.get(value, 0)
            if rank > best_rank:
                best, best_rank = value, rank
        return best

    @staticmethod
    def _guard_state(summary: Any, deviations: Any, inspections: Any) -> str:
        if deviations:
            return "DEVIATION"
        if inspections:
            return "HEALTHY"
        if summary:
            return "LEARNING"
        return "NO EVIDENCE"

    def _apply_guard_filter(self) -> None:
        expression = self.query_one("#guard-filter", Input).value.strip().casefold()
        records = [
            record for record in self._guard_records
            if not expression or expression in json.dumps(record, default=str).casefold()
        ]
        records.sort(
            key=lambda record: (
                0 if record.get("status") == "DEVIATION" else 1,
                self._attention_priority(record.get("severity"))[0],
                str(record.get("target_id") or ""),
            )
        )
        table = self.query_one("#guard-table", DataTable)
        table.clear()
        for record in records:
            table.add_row(
                record["target_id"],
                str(record["status"]),
                str(record["severity"]),
                str(record["last_check"]),
                str(record["violation_count"]),
                str(record["escalation_count"]),
                key=record["target_id"],
            )
        if not self._guard_records:
            output = self.query_one("#guard-output", RichLog)
            output.clear()
            output.write("No Guard-enabled runtime targets are currently available.")
        elif not records:
            output = self.query_one("#guard-output", RichLog)
            output.clear()
            output.write("No Guard targets match the current filter.")

    @classmethod
    def _is_investigation_candidate(cls, record: dict[str, Any]) -> bool:
        try:
            severity = int(record.get("severity") or 0)
        except (TypeError, ValueError):
            severity = 0
        channel = str(record.get("channel") or "").upper()
        return severity >= 30 or channel in {"GUARD", "REPAIR", "INTEGRITY", "AUDIT", "EMERGENCY"}

    def _refresh_investigation_candidates(
        self,
        records: list[dict[str, Any]] | None = None,
        *,
        include_all: bool = False,
    ) -> None:
        source = records if records is not None else self._log_records
        self._investigation_records = [
            record for record in source
            if include_all or self._is_investigation_candidate(record)
        ][:100]
        table = self.query_one("#investigate-table", DataTable)
        table.clear()
        for index, record in enumerate(self._investigation_records, start=1):
            occurred_at = str(record.get("occurred_at") or "")
            table.add_row(
                str(index),
                occurred_at[:19].replace("T", " ") if occurred_at else "-",
                self._log_level(record.get("severity")),
                self._compact_log_text(record.get("channel"), limit=14) or "-",
                self._compact_log_text(record.get("target_id"), limit=24) or "-",
                self._compact_log_text(
                    f"{self._investigation_reason(record)}: {record.get('message') or '-'}",
                    limit=64,
                ),
            )

    @staticmethod
    def _investigation_reason(record: dict[str, Any]) -> str:
        channel = str(record.get("channel") or "").upper()
        try:
            severity = int(record.get("severity") or 0)
        except (TypeError, ValueError):
            severity = 0
        if channel == "GUARD":
            return "Guard evidence"
        if channel == "REPAIR":
            return "Repair activity"
        if channel in {"INTEGRITY", "AUDIT", "EMERGENCY"}:
            return f"{channel.title()} security evidence"
        if severity >= 40:
            return "Error-level event"
        if severity >= 30:
            return "Warning-level event"
        return "Correlated evidence"

    def _update_investigation_scope(self) -> None:
        target = self.query_one("#investigate-target", Input).value.strip() or "all targets"
        incident = self.query_one("#investigate-incident", Input).value.strip() or "any incident"
        call = self.query_one("#investigate-call", Input).value.strip() or "any call"
        minutes = self.query_one("#investigate-minutes", Input).value.strip() or "15"
        model = self.query_one("#investigate-model", Input).value.strip()
        method = f"local Ollama model {model}" if model else "deterministic local analysis"
        self.query_one("#investigate-scope", Static).update(
            f"Scope: last {minutes} minute(s) | {target} | {incident} | {call} | {method} | bounded evidence bundle"
        )

    def _activate_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def _set_operator_context(
        self,
        *,
        target: str | None = None,
        incident: str | None = None,
        call: str | None = None,
    ) -> None:
        self._context_target = target or None
        self._context_incident = incident or None
        self._context_call = call or None
        parts = []
        if self._context_target:
            parts.append(f"target={self._context_target}")
        if self._context_incident:
            parts.append(f"incident={self._context_incident}")
        if self._context_call:
            parts.append(f"call={self._context_call}")
        self.query_one("#operator-context-label", Static).update(
            "Context: " + (" | ".join(parts) if parts else "all targets and incidents")
        )
        self.query_one("#context-clear", Button).disabled = not parts
        self.query_one("#save-capsule-view", Button).disabled = not self._context_incident

    @staticmethod
    def _attention_priority(value: Any) -> tuple[int, str]:
        text = str(value or "INFO").upper()
        order = {"CRITICAL": 0, "ERROR": 1, "HIGH": 1, "WARNING": 2, "WARN": 2, "MEDIUM": 2, "INFO": 3}
        return order.get(text, 3), text

    def _refresh_attention(self) -> None:
        records: list[dict[str, Any]] = []
        runtime = self._last_runtime
        for incident in runtime.get("active_incidents", ()) if runtime else ():
            records.append({
                "priority": "HIGH",
                "kind": "ACTIVE INCIDENT",
                "target_id": str(incident.get("target_id") or "-"),
                "timestamp": str(incident.get("created_at") or incident.get("occurred_at") or ""),
                "summary": str(incident.get("summary") or incident.get("trigger") or "Active incident requires review"),
                "related_tab": "repair",
                "payload": dict(incident),
                "incident_id": str(incident.get("incident_id") or ""),
            })
        for record in self._guard_records:
            for deviation in record.get("deviations", ()):
                explanations = deviation.get("explanations") or () if isinstance(deviation, dict) else ()
                records.append({
                    "priority": str(deviation.get("severity") or "WARNING") if isinstance(deviation, dict) else "WARNING",
                    "kind": "GUARD DEVIATION",
                    "target_id": str(record.get("target_id") or "-"),
                    "timestamp": str(deviation.get("created_at") or deviation.get("occurred_at") or "") if isinstance(deviation, dict) else "",
                    "summary": str(explanations[0] if explanations else "Observed behavior differs from the accepted baseline"),
                    "related_tab": "guard",
                    "payload": dict(deviation) if isinstance(deviation, dict) else {"value": deviation},
                })
        for record in self._repair_records:
            if record.get("state") not in {"WAITING", "FAILED", "ROLLBACK", "BLOCKED", "ERROR"}:
                continue
            records.append({
                "priority": "HIGH" if record.get("state") in {"WAITING", "FAILED", "ERROR"} else "WARNING",
                "kind": f"REPAIR {record.get('state')}",
                "target_id": str(record.get("target_id") or "-"),
                "timestamp": str(record.get("timestamp") or ""),
                "summary": str(record.get("description") or "Repair requires review"),
                "related_tab": "repair",
                "payload": dict(record),
                "incident_id": str((record.get("payload") or {}).get("incident_id") or "") if isinstance(record.get("payload"), dict) else "",
            })
        for violation in self._authority_snapshot.get("violations", ()):
            if not isinstance(violation, dict):
                continue
            records.append({
                "priority": "HIGH",
                "kind": "POLICY VIOLATION",
                "target_id": str(violation.get("target") or violation.get("target_id") or "-"),
                "timestamp": str(violation.get("created_at") or ""),
                "summary": str(violation.get("message") or violation.get("reason") or "Policy guarantee is violated"),
                "related_tab": "policy",
                "payload": dict(violation),
            })
        for component in runtime.get("degraded_components", ()) if runtime else ():
            records.append({
                "priority": "WARNING",
                "kind": "DEGRADED",
                "target_id": "-",
                "timestamp": "",
                "summary": f"Runtime capability is degraded: {component}",
                "related_tab": "overview",
                "payload": {"component": component},
            })
        records.sort(key=lambda item: (self._attention_priority(item.get("priority"))[0], str(item.get("timestamp") or "")), reverse=False)
        self._attention_records = records
        table = self.query_one("#attention-table", DataTable)
        table.clear()
        for index, record in enumerate(records, start=1):
            timestamp = str(record.get("timestamp") or "")
            table.add_row(
                index,
                self._attention_priority(record.get("priority"))[1],
                str(record.get("kind") or "-"),
                self._compact_log_text(record.get("target_id"), limit=26) or "-",
                timestamp[:19].replace("T", " ") if timestamp else "-",
                self._compact_log_text(record.get("summary"), limit=72),
            )
        self.query_one("#attention-list-title", Static).update(
            f"Items requiring operator attention: {len(records)}"
        )
        if not records:
            output = self.query_one("#attention-output", RichLog)
            output.clear()
            output.write("No active issues were found in the currently loaded live and persisted evidence.")

    def _update_data_status(self) -> None:
        refreshed = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        runtime_source = "LIVE" if self._application_running else "UNAVAILABLE/CACHED"
        self.query_one("#data-status", Static).update(
            f"Refreshed {refreshed}  |  Runtime {runtime_source}  |  "
            f"Logs {self._logs_source.upper()} (latest 200)  |  "
            f"Policy {self._authority_source.upper()}  |  Lists may be bounded"
        )

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        try:
            row = event.data_table.get_row(event.row_key)
        except RowDoesNotExist:
            # A refresh may rebuild a table while Textual still has a queued
            # selection event for one of its former rows.
            return

        if event.data_table.id == "incident-capsule-table":
            if not row:
                return
            try:
                record = [
                    item for item in self._capsule_records
                    if self._capsule_matches_filter(
                        item,
                        self.query_one("#incident-capsule-filter", Input).value,
                    )
                ][int(row[0]) - 1]
            except (TypeError, ValueError, IndexError):
                return
            await self._select_incident_capsule(record)
            return

        if event.data_table.id == "incident-artifact-table":
            if not row:
                return
            try:
                record = self._incident_artifact_records[int(row[0]) - 1]
            except (TypeError, ValueError, IndexError):
                return
            await self._select_incident_artifact(record)
            return

        if event.data_table.id == "incident-timeline-table":
            if not row:
                return
            try:
                record = self._incident_timeline_records[int(row[0]) - 1]
            except (TypeError, ValueError, IndexError):
                return
            await self._select_incident_timeline(record)
            return

        if event.data_table.id == "attention-table":
            if not row:
                return
            try:
                record = self._attention_records[int(row[0]) - 1]
            except (TypeError, ValueError, IndexError):
                return
            self._selected_attention_record = record
            target = str(record.get("target_id") or "")
            self._set_operator_context(
                target=target if target != "-" else None,
                incident=str(record.get("incident_id") or "") or None,
            )
            self.query_one("#attention-detail-title", Static).update(
                f"{record.get('kind', 'Issue')} | {target or 'unscoped'}"
            )
            self.query_one("#attention-open", Button).disabled = False
            self.query_one("#attention-investigate", Button).disabled = False
            output = self.query_one("#attention-output", RichLog)
            output.clear()
            output.write(
                f"[b]Why this needs attention[/b]\n{record.get('summary') or '-'}\n"
                f"[b]Priority[/b] {record.get('priority') or '-'}\n"
                f"[b]Recommended next step[/b] Open {record.get('related_tab') or 'the related view'} "
                "or investigate the correlated evidence."
            )
            output.write("\n[b]Technical details[/b]")
            output.write(json.dumps(record.get("payload") or {}, indent=2, sort_keys=True, default=str))
            return
        if event.data_table.id == "guard-table":
            if not row:
                return
            target_id = str(row[0])
            self._set_operator_context(target=target_id)
            record = next((item for item in self._guard_records if item["target_id"] == target_id), None)
            if record is None:
                return
            self._selected_guard_target = target_id
            for button_id in (
                "#guard-summary", "#guard-events", "#guard-deviations",
                "#guard-inspections", "#guard-assess", "#guard-open-behavior",
                "#guard-open-logs", "#guard-open-investigate",
            ):
                self.query_one(button_id, Button).disabled = False
            confirmation = self.query_one("#guard-baseline-confirm", Checkbox)
            confirmation.value = False
            confirmation.disabled = record.get("summary") is None
            self.query_one("#guard-baseline", Button).disabled = True
            self.query_one("#guard-detail-title", Static).update(
                f"Guard target {target_id} | {record.get('status')} | severity {record.get('severity')}"
            )
            output = self.query_one("#guard-output", RichLog)
            output.clear()
            output.write(
                f"[b]Operational assessment[/b] {record.get('status')}\n"
                f"[b]Last evidence[/b] {record.get('last_check')}\n"
                f"[b]Active findings[/b] {record.get('violation_count')}\n"
                f"[b]Escalations/decisions[/b] {record.get('escalation_count')}"
            )
            deviations = record.get("deviations") or ()
            if deviations:
                output.write("\n[b]Why this target needs attention[/b]")
                for deviation in deviations[:10]:
                    explanations = deviation.get("explanations") or () if isinstance(deviation, dict) else ()
                    output.write(
                        f"  • {explanations[0] if explanations else 'Observed behavior departed from expectations'}"
                    )
            elif record.get("status") == "NO EVIDENCE":
                output.write("\n[yellow]No Guard evidence has been recorded yet; this is not the same as healthy.[/yellow]")
            elif record.get("status") == "LEARNING":
                output.write("\n[yellow]Guard has observations but has not established enough evidence for a healthy assessment.[/yellow]")
            if record.get("summary") is None:
                output.write("\nBaseline acceptance is unavailable because no aggregate summary exists.")
            else:
                output.write("\nReview Summary, Events, Deviations, and Inspections before accepting a baseline.")
            return

        if event.data_table.id == "investigate-table":
            try:
                record = self._investigation_records[int(row[0]) - 1]
            except (TypeError, ValueError, IndexError):
                return
            self._selected_investigation_record = record
            target = str(record.get("target_id") or "")
            self._set_operator_context(
                target=target or None,
                incident=str(record.get("incident_id") or "") or None,
                call=str(record.get("call_id") or "") or None,
            )
            if target:
                self.query_one("#investigate-target", Input).value = target
            if record.get("incident_id"):
                self.query_one("#investigate-incident", Input).value = str(record["incident_id"])
            if record.get("call_id"):
                self.query_one("#investigate-call", Input).value = str(record["call_id"])
            self.query_one("#investigate-detail-title", Static).update(
                f"Selected {record.get('channel', '-')} evidence | {target or 'no target'}"
            )
            self._write_json("#investigate-output", record)
            return

        if event.data_table.id == "logs-table":
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
            self._selected_log_record = record
            self._set_operator_context(
                target=str(record.get("target_id") or "") or None,
                incident=str(record.get("incident_id") or "") or None,
                call=str(record.get("call_id") or "") or None,
            )
            self.query_one("#logs-investigate", Button).disabled = False
            self.query_one("#logs-related", Button).disabled = False
            output = self.query_one("#logs-output", RichLog)
            output.clear()
            output.write(
                f"[b]{self._log_level(record.get('severity'))} {record.get('channel') or '-'}[/b]\n"
                f"{record.get('message') or '-'}\n"
                f"Target: {record.get('target_id') or 'unscoped'}\n"
                f"Incident: {record.get('incident_id') or 'none'}  Call: {record.get('call_id') or 'none'}\n"
                "Use Investigate correlated for identifier-based evidence gathering; Open related tab follows channel/target routing."
            )
            output.write("\n[b]Technical record[/b]")
            output.write(json.dumps(record, indent=2, sort_keys=True, default=str))
            return

        if event.data_table.id == "behavior-table":
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._displayed_behavior_records[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            snapshot_id = str(record.get("snapshot_id") or "")
            if not snapshot_id:
                return
            self._selected_behavior_snapshot = snapshot_id
            self._behavior_view_mode = "detail"
            self.query_one("#behavior-archive-reason", Input).value = ""
            self.query_one("#behavior-manage-confirm", Checkbox).value = False
            behavior_target = str((record.get("subject") or {}).get("target_id") or "")
            self._set_operator_context(target=behavior_target or None)
            self._refresh_behavior_actions()
            subject = record.get("subject") or {}
            subject_value = (
                subject.get("module_name")
                if record.get("scope") == "module"
                else subject.get("target_id")
            )
            if subject_value:
                self.query_one("#behavior-subject", Input).value = str(subject_value)
            try:
                response = await self._request("behavior-get", snapshot_id=snapshot_id)
                self._show_behavior_snapshot(response.get("envelope") or {}, summary=record)
            except Exception as exc:
                self._write_json(
                    "#behavior-output",
                    {"error": f"{type(exc).__name__}: {exc}", "snapshot_id": snapshot_id},
                )
            return

        if event.data_table.id == "repair-table":
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._displayed_repair_records[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            self._selected_repair_record = record
            payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
            self._set_operator_context(
                target=str(record.get("target_id") or "") or None,
                incident=str(payload.get("incident_id") or "") or None,
            )
            self._repair_source_view = False
            self._selected_repair_approval = (
                str(record.get("episode_id"))
                if record.get("record_kind") == "pending_approval" and record.get("episode_id")
                else None
            )
            actionable = self._selected_repair_approval is not None and bool(self._application_running)
            confirmation = self.query_one("#repair-approve-confirm", Checkbox)
            confirmation.value = False
            confirmation.disabled = not actionable
            self.query_one("#repair-approve", Button).disabled = True
            self.query_one("#repair-reject", Button).disabled = True
            for button_id in ("#repair-open-logs", "#repair-open-guard", "#repair-open-investigate"):
                self.query_one(button_id, Button).disabled = False
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
            if record.get("record_kind") == "pending_approval":
                approval = record.get("payload") or {}
                output = self.query_one("#repair-output", RichLog)
                output.clear()
                output.write(
                    f"[b]Decision required[/b] Activate candidate for {record.get('target_id')}\n"
                    f"[b]Episode[/b] {record.get('episode_id')}\n"
                    f"[b]Candidate[/b] {approval.get('candidate_id', '-')}\n"
                    f"[b]Expected current version[/b] {approval.get('expected_function_version', '-')}\n"
                    f"[b]Why approval is required[/b] {approval.get('reason', '-')}\n"
                    f"[b]Artifact hash[/b] {approval.get('artifact_hash', '-')}\n"
                    f"[b]Authority generation[/b] {approval.get('authority_policy_generation', '-')}\n"
                    "[yellow]Evidence limitation: the approval record does not currently include the validation backend, "
                    "complete validation report, or original-source diff. Review candidate source and triggering evidence; "
                    "approval does not prove those missing assurances.[/yellow]"
                )
            else:
                self._write_json("#repair-output", record.get("payload", record))
            return

        if event.data_table.id == "policy-table":
            if not row:
                return
            try:
                record_number = int(row[0])
                record = self._authority_rows[record_number - 1]
            except (TypeError, ValueError, IndexError):
                return
            self._selected_authority_lease = str(record.get("lease_id")) if record.get("lease_id") else None
            release_confirm = self.query_one("#policy-release-confirm", Checkbox)
            release_confirm.value = False
            release_confirm.disabled = self._selected_authority_lease is None
            self.query_one("#policy-release", Button).disabled = True
            self.query_one("#policy-detail-title", Static).update(
                f"{record.get('kind', 'policy')} | {record.get('authority_id') or 'not configured'}"
            )
            self._write_json("#policy-output", record)
            return

        if event.data_table.id != "targets-table":
            return
        if not row:
            return
        target_id = str(row[0])
        self._selected_target = target_id
        self._set_operator_context(target=target_id)
        for button_id in (
            "#overview-guard", "#overview-behavior", "#overview-logs", "#overview-investigate"
        ):
            self.query_one(button_id, Button).disabled = False
        self.query_one("#behavior-subject", Input).value = target_id
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
            target_record = next(
                (item for item in self._target_records if str(item.get("target_id")) == target_id),
                {},
            )
            details = self.query_one("#target-details", RichLog)
            details.clear()
            details.write(
                f"[b]{target_id}[/b]\n"
                f"Health: {target_record.get('status', 'READY')}\n"
                f"Needs attention: {self._target_attention_reason(target_record)}\n"
                f"Repair mode: {target_record.get('repair_mode') or '-'}; "
                f"operator authority: {target_record.get('repair_authority') or '-'}; "
                f"Guard: {'enabled' if target_record.get('guard_enabled') else 'disabled'}\n"
                f"Slot role: {self._slot_role_display(target_record.get('slot_role'))}; "
                f"adaptive observation: {self._observation_display(target_record.get('observation_level'), target_record.get('slot_role'))}; "
                f"lifecycle: {target_record.get('lifecycle_label') or target_record.get('lifecycle_stage') or '-'}\n"
                f"Escalation reason: {target_record.get('escalation_reason') or 'none'}\n"
                "Use the buttons above to inspect evidence or start an investigation."
            )
            details.write("\n[b]Technical state and effective policy[/b]")
            details.write(json.dumps(
                {"state": state.get("state"), "policy": policy.get("policy")},
                indent=2,
                sort_keys=True,
                default=str,
            ))
        except Exception as exc:
            self._write_json(
                "#target-details",
                {"error": f"{type(exc).__name__}: {exc}", "target": target_id},
            )

    @staticmethod
    def _behavior_short_hash(value: Any) -> str:
        text = str(value or "-")
        return text[:12] if text != "-" else text

    async def refresh_behavior(self) -> None:
        previous_records = {
            str(item.get("snapshot_id") or ""): dict(item)
            for item in self._behavior_records
            if item.get("snapshot_id")
        }
        previous_selection = self._behavior_record(self._selected_behavior_snapshot)
        previous_subject = str((previous_selection or {}).get("subject_key") or "")
        previous_generation = str((previous_selection or {}).get("generation_id") or "")
        response = await self._request("behavior-list")
        collection_id = str(response.get("collection_id") or "")
        collection_changed = collection_id != (self._behavior_collection_id or "")
        if collection_changed:
            previous_subject = ""
            previous_generation = ""
            self._selected_behavior_snapshot = None
            self._behavior_references.clear()
            self._behavior_last_comparison = None
            self._behavior_view_mode = "detail"
        self._behavior_collection_id = collection_id
        self._behavior_loaded_revision = int(response.get("revision") or 0)
        self._behavior_records = [
            dict(item) for item in response.get("snapshots", ()) if isinstance(item, dict)
        ]
        snapshot_ids = {str(item.get("snapshot_id") or "") for item in self._behavior_records}
        if not collection_changed:
            # A compact generation summary advances to a new representative epoch
            # as evidence arrives. Keep the exact operator-selected reference
            # artifact pinned and visible instead of silently moving the reference.
            for reference_id in self._behavior_references.values():
                pinned = previous_records.get(reference_id)
                if reference_id not in snapshot_ids and pinned is not None:
                    pinned["pinned_reference_epoch"] = True
                    self._behavior_records.append(pinned)
                    snapshot_ids.add(reference_id)
        if self._selected_behavior_snapshot not in snapshot_ids:
            replacement = next(
                (
                    item for item in self._behavior_records
                    if previous_subject
                    and str(item.get("subject_key") or "") == previous_subject
                    and (
                        not previous_generation
                        or str(item.get("generation_id") or "") == previous_generation
                    )
                ),
                None,
            )
            self._selected_behavior_snapshot = (
                str(replacement.get("snapshot_id") or "") if replacement else None
            )
        self._behavior_references = {
            subject: snapshot_id
            for subject, snapshot_id in self._behavior_references.items()
            if snapshot_id in snapshot_ids
        }
        for record in self._behavior_records:
            if self._behavior_is_zero_call(record):
                continue
            subject = str(record.get("subject_key") or "")
            self._behavior_references.setdefault(subject, str(record.get("snapshot_id") or ""))
        for record in self._behavior_records:
            subject = str(record.get("subject_key") or "")
            self._behavior_references.setdefault(subject, str(record.get("snapshot_id") or ""))
        self._apply_behavior_filter()
        if not self._behavior_records:
            self._behavior_last_comparison = None
            self._behavior_view_mode = "detail"
            self.query_one("#behavior-detail-title", Static).update("Behavior snapshots")
            output = self.query_one("#behavior-output", RichLog)
            output.clear()
            output.write(
                "No behavior snapshots have been saved. Run the target workload first, then save or refresh observations."
            )
        elif self._selected_behavior_snapshot and self._behavior_view_mode != "comparison":
            selected = self._behavior_record(self._selected_behavior_snapshot)
            if selected is not None:
                detail = await self._request(
                    "behavior-get", snapshot_id=self._selected_behavior_snapshot
                )
                self._show_behavior_snapshot(detail.get("envelope") or {}, summary=selected)
        self._refresh_behavior_actions()

    def _apply_behavior_filter(self) -> None:
        expression = self.query_one("#behavior-filter", Input).value.strip().casefold()
        tokens = expression.split()
        show_zero_calls = self.query_one("#behavior-show-zero-calls", Checkbox).value
        show_older = self.query_one("#behavior-show-older", Checkbox).value
        hidden_zero_calls = 0
        hidden_older = 0
        subject_generation_rank: dict[str, int] = {}
        self._displayed_behavior_records = []
        for record in self._behavior_records:
            subject_key = str(record.get("subject_key") or "")
            snapshot_id = str(record.get("snapshot_id") or "")
            is_reference = snapshot_id == self._behavior_references.get(subject_key)
            rank = subject_generation_rank.get(subject_key, 0) + 1
            subject_generation_rank[subject_key] = rank
            if rank > 3 and not show_older and not is_reference:
                hidden_older += 1
                continue
            if self._behavior_is_zero_call(record) and not show_zero_calls and not is_reference:
                hidden_zero_calls += 1
                continue
            evidence, _coverage = self._behavior_evidence(record)
            integrity = "invalid" if record.get("verified") is False else str(
                (record.get("integrity") or {}).get("signature_state") or "verified"
            ).casefold()
            fields = {
                "subject": str(record.get("subject_key") or "").casefold(),
                "generation": str(record.get("generation_id") or "").casefold(),
                "coverage": str((record.get("profile") or {}).get("coverage_kind") or "partial").casefold(),
                "evidence": evidence.casefold(),
                "integrity": integrity,
            }
            searchable = (json.dumps(record, default=str) + " " + " ".join(fields.values())).casefold()
            matched = True
            for token in tokens:
                if ":" in token:
                    name, value = token.split(":", 1)
                    if name in fields and value not in fields[name]:
                        matched = False
                        break
                elif token not in searchable:
                    matched = False
                    break
            if matched:
                self._displayed_behavior_records.append(record)

        table = self.query_one("#behavior-table", DataTable)
        table.clear()
        for index, record in enumerate(self._displayed_behavior_records, start=1):
            subject = record.get("subject") or {}
            label = (
                subject.get("module_name")
                if record.get("scope") == "module"
                else subject.get("target_id") or record.get("subject_key")
            )
            first_seen = self._behavior_display_time(record.get("first_seen_at"))
            last_seen = self._behavior_display_time(record.get("last_seen_at"))
            evidence, calls_target = self._behavior_evidence(record)
            snapshot_id = str(record.get("snapshot_id") or "")
            subject_key = str(record.get("subject_key") or "")
            is_reference = snapshot_id == self._behavior_references.get(subject_key)
            role = Text("REFERENCE", style="bold green") if is_reference else Text("")
            rendered_label = Text(str(label or "-"), style="green" if is_reference else None)
            rendered_generation = Text(
                self._behavior_short_hash(record.get("generation_id")),
                style="green" if is_reference else None,
            )
            integrity = "INVALID" if record.get("verified") is False else str(
                (record.get("integrity") or {}).get("signature_state") or "VERIFIED"
            )
            table.add_row(
                str(index),
                role,
                rendered_label,
                rendered_generation,
                first_seen,
                last_seen,
                calls_target,
                self._behavior_activity_histogram(record),
                evidence,
                integrity,
            )
        subjects = len({str(item.get("subject_key")) for item in self._behavior_records})
        self.query_one("#behavior-list-title", Static).update(
            f"Behavior generations: showing {len(self._displayed_behavior_records)}/{len(self._behavior_records)} "
            f"across {subjects} subject{'s' if subjects != 1 else ''}; cumulative evidence preferred per generation; "
            f"{hidden_zero_calls} zero-call generation{'s' if hidden_zero_calls != 1 else ''} hidden; "
            f"{hidden_older} older generation{'s' if hidden_older != 1 else ''} hidden"
        )

    @staticmethod
    def _behavior_is_zero_call(record: dict[str, Any]) -> bool:
        profile = record.get("profile") or {}
        calls = int(profile.get("coverage_call_count", profile.get("call_count")) or 0)
        return calls == 0

    @staticmethod
    def _behavior_display_time(value: Any) -> str:
        text = str(value or "-")
        if "T" in text:
            return text.replace("T", " ").replace("+00:00", "Z")[:19]
        return text

    @staticmethod
    def _behavior_activity_histogram(record: dict[str, Any]) -> str:
        calls = [int(item.get("calls") or 0) for item in record.get("activity_windows", ())]
        if not calls:
            return "-"
        levels = "▁▂▃▄▅▆▇█"
        maximum = max(calls)
        if maximum <= 0:
            return "▁" * len(calls)
        return "".join(levels[min(len(levels) - 1, round(value * (len(levels) - 1) / maximum))] for value in calls)

    def _behavior_record(self, snapshot_id: str | None) -> dict[str, Any] | None:
        return next(
            (
                item for item in self._behavior_records
                if str(item.get("snapshot_id") or "") == str(snapshot_id or "")
            ),
            None,
        )

    def _refresh_behavior_actions(self) -> None:
        selected = self._behavior_record(self._selected_behavior_snapshot)
        subject = str((selected or {}).get("subject_key") or "")
        reference = self._behavior_record(self._behavior_references.get(subject))
        self.query_one("#behavior-set-reference", Button).disabled = not (
            selected and selected is not reference
        )
        self.query_one("#behavior-compare", Button).disabled = not (
            selected and reference and selected is not reference
        )
        self.query_one("#behavior-assess-comparison", Button).disabled = self._behavior_last_comparison is None
        manage_confirm = self.query_one("#behavior-manage-confirm", Checkbox)
        reason = self.query_one("#behavior-archive-reason", Input).value.strip()
        manage_confirm.disabled = selected is None or not reason
        if manage_confirm.disabled:
            manage_confirm.value = False
        confirmed = bool(selected and reason and manage_confirm.value)
        self.query_one("#behavior-archive", Button).disabled = not confirmed

        def identity(record: dict[str, Any] | None) -> str:
            if record is None:
                return "not set"
            return (
                f"{record.get('subject_key') or '-'} "
                f"[{self._behavior_short_hash(record.get('code_hash'))}] "
                f"snapshot {self._behavior_short_hash(record.get('snapshot_id'))}"
            )

        self.query_one("#behavior-selection-status", Static).update(
            f"Reference: {identity(reference)}  |  Selected: {identity(selected)}  |  "
            + (
                "Choose another generation for this subject, then Compare."
                if selected is reference else
                "Compare is available; Set Reference makes the selected generation green."
                if selected else
                "Select a generation to inspect or compare."
            )
        )

    @staticmethod
    def _behavior_evidence(record: dict[str, Any]) -> tuple[str, str]:
        profile = record.get("profile") or {}
        calls = int(profile.get("coverage_call_count", profile.get("call_count")) or 0)
        coverage_kind = str(profile.get("coverage_kind") or "snapshot")
        provenance = profile.get("sampling_provenance") or {}
        target = int(provenance.get("statistics_target") or 0)
        prefix = "" if coverage_kind == "generation" else "partial "
        calls_target = prefix + (f"{calls}/{target}" if target else f"{calls}/?")
        if calls <= 0:
            return "NO DATA", calls_target
        if not target:
            return "UNKNOWN", calls_target
        if calls < target:
            return "PRELIMINARY", calls_target
        return "TARGET REACHED", calls_target

    @staticmethod
    def _behavior_bar(value: float, maximum: float, *, width: int = 18) -> str:
        if maximum <= 0:
            return "·" * width
        filled = max(0, min(width, round(width * value / maximum)))
        return "█" * filled + "·" * (width - filled)

    @staticmethod
    def _behavior_delta(change: dict[str, Any]) -> str:
        relative = change.get("relative")
        absolute = change.get("absolute", 0)
        if relative is None:
            return f"{absolute:+} (new base)"
        return f"{absolute:+} ({relative * 100:+.1f}%)"

    def _show_behavior_snapshot(
        self,
        envelope: dict[str, Any],
        *,
        summary: dict[str, Any] | None = None,
    ) -> None:
        self._behavior_view_mode = "detail"
        snapshot = envelope.get("snapshot") or {}
        integrity = envelope.get("integrity") or {}
        subject = snapshot.get("subject") or {}
        profile = snapshot.get("profile") or {}
        evidence, calls_target = self._behavior_evidence(summary or snapshot)
        title = str(snapshot.get("subject_key") or snapshot.get("snapshot_id") or "Behavior snapshot")
        self.query_one("#behavior-detail-title", Static).update(title)
        output = self.query_one("#behavior-output", RichLog)
        output.clear()
        signature_state = integrity.get("signature_state", "-")
        signature_detail = (
            f"{signature_state} (verified on load)"
            if integrity.get("artifact_signature")
            else str(signature_state)
        )
        output.write(
            f"[b]Snapshot[/b] {snapshot.get('snapshot_id', '-')}\n"
            f"[b]Created[/b] {snapshot.get('created_at', '-')}\n"
            f"[b]Generation first seen[/b] {(summary or {}).get('first_seen_at', snapshot.get('observation_started_at') or snapshot.get('created_at', '-'))}\n"
            f"[b]Generation last seen[/b] {(summary or {}).get('last_seen_at', snapshot.get('observation_ended_at') or snapshot.get('created_at', '-'))}\n"
            f"[b]Saved windows[/b] {(summary or {}).get('snapshot_count', 1)}  "
            f"[b]Call activity[/b] {self._behavior_activity_histogram(summary or {}) or '-'} "
            f"(oldest → newest; {(summary or {}).get('activity_kind', 'single snapshot')})\n"
            f"[b]Epoch[/b] {snapshot.get('epoch_sequence') or '-'}  id={snapshot.get('epoch_id') or '-'}  "
            f"samples={snapshot.get('first_sample_sequence') or '-'}..{snapshot.get('last_sample_sequence') or '-'}  "
            f"complete={'yes' if snapshot.get('complete_epoch') else 'no'}\n"
            f"[b]Scope[/b] {snapshot.get('scope', '-')}\n"
            f"[b]Subject[/b] {subject.get('module_name', '-')}{':' + str(subject.get('qualified_name')) if subject.get('qualified_name') else ''}\n"
            f"[b]Code hash[/b] {snapshot.get('code_hash_kind', '-')}: {snapshot.get('code_hash', '-')}\n"
            f"[b]Generation[/b] {self._behavior_short_hash(snapshot.get('generation_id'))}\n"
            f"[b]Monitoring[/b] {self._behavior_short_hash(snapshot.get('monitoring_fingerprint'))}\n"
            f"[b]Environment[/b] {snapshot.get('environment_fingerprint') or 'not labeled'}\n"
            f"[b]Workload[/b] {snapshot.get('workload_label') or 'not labeled'}\n"
            f"[b]Seal reason[/b] {snapshot.get('seal_reason') or '-'}\n"
            f"[b]Snapshot SHA-256[/b] {integrity.get('content_sha256', '-')}\n"
            f"[b]Signature[/b] {signature_detail}"
            f"\n[b]Evidence[/b] {evidence} ({calls_target} completed calls/collection target)"
        )
        if summary is not None:
            summary_profile = summary.get("profile") or {}
            output.write(
                f"[b]Generation coverage[/b] {summary_profile.get('coverage_call_count', 0)} completed calls "
                f"across {summary_profile.get('coverage_snapshot_count', summary.get('snapshot_count', 1))} "
                f"verified disjoint epoch(s); the artifact below contains "
                f"{profile.get('call_count', 0)} call(s)."
            )
            if int(summary_profile.get("coverage_gap_count") or 0):
                output.write(
                    f"[yellow]Evidence continuity has {summary_profile.get('coverage_gap_count')} gap(s); "
                    f"approximately {summary_profile.get('coverage_missing_sample_count', 0)} sample sequence(s) "
                    "were not materialized. Later disjoint samples are included in coverage.[/yellow]"
                )
        output.write(
            "[yellow]This indicates evidence volume only; it does not guarantee statistical accuracy or representative workload coverage.[/yellow]"
        )
        output.write(
            f"\n[b]Behavior[/b] calls={profile.get('call_count', 0)} events={profile.get('event_count', 0)}"
            f" success={profile.get('success_count', 0)} failure={profile.get('failure_count', 0)}"
        )
        duration = dict((profile.get("statistics") or {}).get("duration_seconds") or {})
        if duration:
            output.write("\n[b]Duration statistics (seconds)[/b]")
            values = []
            for key in ("minimum", "p10", "p50", "average", "p90", "p95", "p99", "maximum"):
                value = duration.get(key)
                if value is not None:
                    values.append(f"{key}={float(value):.6g}")
            if values:
                output.write("  " + "  ".join(values))
            output.write(
                f"  observations={duration.get('count', 0)} reservoir={duration.get('reservoir_size', 0)}"
            )
        provenance = profile.get("sampling_provenance") or {}
        output.write(
            f"\n[b]Observation provenance[/b] completed_calls={provenance.get('completed_call_samples', profile.get('call_count', 0))} "
            f"event_samples={provenance.get('event_samples', profile.get('event_count', 0))} "
            f"statistics_target={provenance.get('statistics_target', '?')} "
            f"resource_coverage={'complete' if profile.get('resource_coverage_complete', True) else 'TRUNCATED'}"
        )
        strata = provenance.get("strata") or {}
        if strata:
            output.write("\n[b]Sampling strata[/b]")
            for stage, details in sorted(strata.items()):
                output.write(
                    f"  {stage}: samples={details.get('sample_count', 0)} "
                    f"success={details.get('success_count', 0)} failure={details.get('failure_count', 0)}"
                )
        if profile.get("resource_coverage_complete") is False:
            output.write(
                "[yellow]Resource set is truncated; omitted resources must not be interpreted as never observed.[/yellow]"
            )
        for kind, count in sorted((profile.get("event_kind_counts") or {}).items()):
            output.write(f"  {kind}: {count}")
        for key, label in (
            ("network_destinations", "Network"),
            ("filesystem_roots", "Filesystem"),
            ("subprocesses", "Subprocesses"),
            ("imports", "Imports"),
            ("dynamic_code_operations", "Dynamic code"),
        ):
            values = profile.get(key) or ()
            if values:
                output.write(f"\n[b]{label}[/b]")
                for value in values[:30]:
                    output.write(f"  • {value}")
                if len(values) > 30:
                    output.write(f"  … {len(values) - 30} more")
        children = snapshot.get("children") or ()
        if children:
            output.write("\n[b]Module behavior tree[/b]")
            for child in children:
                child_subject = child.get("subject") or {}
                child_profile = child.get("profile") or {}
                output.write(
                    f"  ├─ {child_subject.get('target_id') or child.get('subject_key')} "
                    f"[{self._behavior_short_hash(child.get('code_hash'))}] "
                    f"calls={child_profile.get('call_count', 0)} events={child_profile.get('event_count', 0)}"
                )

    def _show_behavior_comparison(self, comparison: dict[str, Any]) -> None:
        self._behavior_view_mode = "comparison"
        self._behavior_last_comparison = comparison
        self._refresh_behavior_actions()
        subject_a = comparison.get("subject_a") or "-"
        subject_b = comparison.get("subject_b") or "-"
        self.query_one("#behavior-detail-title", Static).update(
            f"Reference {subject_a} → selected {subject_b}"
        )
        output = self.query_one("#behavior-output", RichLog)
        output.clear()
        output.write(
            "[b]Comparison scope[/b] Behavior metrics below compare one representative sealed epoch "
            "from each row. Generation coverage is cumulative across all verified disjoint epochs and "
            "is shown separately; it is not substituted into epoch-local event statistics."
        )
        for marker, operand in (
            ("Reference", comparison.get("snapshot_a") or {}),
            ("Selected", comparison.get("snapshot_b") or {}),
        ):
            coverage = comparison.get(
                "generation_coverage_a" if marker == "Reference" else "generation_coverage_b"
            ) or {}
            calls = int(operand.get("call_count") or 0)
            target = int(operand.get("statistics_target") or 0)
            evidence = "target reached" if target and calls >= target else "preliminary"
            output.write(
                f"[b]{marker}[/b] {operand.get('subject_key') or '-'}\n"
                f"  snapshot={operand.get('snapshot_id') or 'live'}  created={operand.get('created_at') or '-'}\n"
                f"  code={self._behavior_short_hash(operand.get('code_hash'))}  "
                f"representative_epoch={operand.get('epoch_sequence') or '-'}  "
                f"samples={operand.get('first_sample_sequence') or '-'}..{operand.get('last_sample_sequence') or '-'}\n"
                f"  epoch calls={calls}/{target or '?'} ({evidence})  events={operand.get('event_count', 0)}\n"
                f"  generation coverage={coverage.get('calls', calls)}/{coverage.get('target', target) or '?'} "
                f"across {coverage.get('epochs', 1)} verified epoch(s)"
            )
        output.write(
            "[yellow]Collection targets indicate evidence volume, not guaranteed accuracy or workload representativeness.[/yellow]"
        )
        semantic_changes = comparison.get("semantic_changes") or ()
        output.write("\n[b]What changed between the representative epochs[/b]")
        if semantic_changes:
            for change in semantic_changes[:40]:
                marker = "+" if change.get("change") == "started" else "−"
                output.write(f"  {marker} {change.get('description')}")
            if len(semantic_changes) > 40:
                output.write(f"  … {len(semantic_changes) - 40} more behavior changes")
        else:
            output.write(
                "  No observed filesystem, network, subprocess, import, or dynamic-code resources were added or removed."
            )
        outcomes = comparison.get("outcomes") or {}
        outcome_changes = [
            change for change in outcomes.values()
            if int(change.get("absolute") or 0) != 0
        ]
        if outcome_changes:
            output.write("[b]Call outcome changes[/b]")
            for change in outcome_changes:
                output.write(
                    f"  {change.get('label')}: {change.get('before', 0)} → {change.get('after', 0)}"
                )
        code_changed = bool(comparison.get("code_hash_changed"))
        output.write(
            f"[b]Code generation[/b] {'CHANGED' if code_changed else 'same'}\n"
            f"Reference {self._behavior_short_hash(comparison.get('code_hash_a'))}  →  "
            f"selected {self._behavior_short_hash(comparison.get('code_hash_b'))}"
        )
        if comparison.get("monitoring_changed"):
            output.write("[yellow]Monitoring configuration changed; this comparison spans behavior generations.[/yellow]")
        if comparison.get("cross_subject"):
            output.write("[yellow]Cross-subject comparison: interpret deltas as exploratory, not baseline drift.[/yellow]")
        for label in ("calls", "events", "events_per_call"):
            change = comparison.get(label) or {}
            before = float(change.get("before") or 0)
            after = float(change.get("after") or 0)
            maximum = max(before, after, 1.0)
            output.write(
                f"\n[b]{label}[/b]  {self._behavior_delta(change)}\n"
                f" Reference {self._behavior_bar(before, maximum)} {before:.2f}\n"
                f" Selected  {self._behavior_bar(after, maximum)} {after:.2f}"
            )
        duration_changes = comparison.get("duration_statistics") or {}
        if duration_changes:
            output.write("\n[b]Duration distribution changes[/b]")
            for key in ("minimum", "p10", "p50", "average", "p90", "p95", "p99", "maximum"):
                change = duration_changes.get(key)
                if not change:
                    continue
                before = float(change.get("before") or 0)
                after = float(change.get("after") or 0)
                maximum = max(abs(before), abs(after), 1e-12)
                output.write(
                    f" {key}: {self._behavior_delta(change)}\n"
                    f"   Reference {self._behavior_bar(before, maximum, width=14)} {before:.6g}\n"
                    f"   Selected  {self._behavior_bar(after, maximum, width=14)} {after:.6g}"
                )
        kind_changes = comparison.get("event_kind_changes") or ()
        if kind_changes:
            output.write("\n[b]Event-kind changes[/b]")
            for change in kind_changes:
                before = float(change.get("before") or 0)
                after = float(change.get("after") or 0)
                maximum = max(before, after, 1.0)
                output.write(
                    f" {change.get('label')}: {self._behavior_delta(change)}\n"
                    f"   Reference {self._behavior_bar(before, maximum, width=14)} {before:.0f}\n"
                    f"   Selected  {self._behavior_bar(after, maximum, width=14)} {after:.0f}"
                )
        resource_changes = comparison.get("resource_changes") or {}
        changed_resources = False
        for key, values in resource_changes.items():
            added = values.get("added") or ()
            removed = values.get("removed") or ()
            if not added and not removed:
                continue
            if not changed_resources:
                output.write("\n[b]Resource novelty[/b]")
                changed_resources = True
            if added:
                output.write(f" {key}: + {', '.join(map(str, added[:12]))}")
            if removed:
                output.write(f" {key}: - {', '.join(map(str, removed[:12]))}")
        tree = comparison.get("tree_changes") or ()
        if tree:
            output.write("\n[b]Function tree[/b]")
            for item in tree:
                marker = "*" if item.get("state") != "unchanged" or item.get("code_hash_changed") else " "
                output.write(
                    f" {marker} {item.get('subject_key')}: {item.get('state')}"
                    + (" [code changed]" if item.get("code_hash_changed") else "")
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
        try:
            await self.refresh_guard()
        except Exception as exc:
            self._write_json(
                "#guard-output",
                {"error": f"Unable to refresh Guard status: {type(exc).__name__}: {exc}"},
            )
        try:
            await self.refresh_behavior()
        except Exception as exc:
            self._write_json(
                "#behavior-output",
                {"error": f"Unable to refresh behavior snapshots: {type(exc).__name__}: {exc}"},
            )
        await self.refresh_logs()
        try:
            await self.refresh_incident_capsules()
        except Exception as exc:
            self._write_json(
                "#incident-capsule-output",
                {"error": f"Unable to refresh Incident Capsules: {type(exc).__name__}: {exc}"},
            )
        self._refresh_attention()
        self._update_data_status()

    async def action_refresh(self) -> None:
        await self.refresh_all()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "logs-filter":
            self._apply_log_filter()
        elif event.input.id == "targets-filter":
            self._apply_target_filter()
        elif event.input.id == "guard-filter":
            self._apply_guard_filter()
        elif event.input.id == "behavior-filter":
            self._apply_behavior_filter()
        elif event.input.id == "repair-filter":
            self._apply_repair_filter()
        elif event.input.id == "incident-capsule-filter":
            self._apply_incident_capsule_filter()
        elif event.input.id in {"policy-target", "policy-path", "policy-value", "policy-duration", "policy-reason"}:
            self._policy_preview = None
            self.query_one("#policy-confirm", Checkbox).value = False
            self.query_one("#policy-confirm", Checkbox).disabled = True
            self.query_one("#policy-apply", Button).disabled = True
            self.query_one("#policy-preview-output", Static).update("Inputs changed; preview the policy change again.")
            if event.input.id == "policy-reason":
                signed_confirm = self.query_one("#policy-signed-confirm", Checkbox)
                signed_confirm.value = False
                signed_confirm.disabled = not bool(
                    event.value.strip()
                    and self.query_one("#policy-signed-descriptor", Input).value.strip()
                )
                self.query_one("#policy-apply-signed", Button).disabled = True
        elif event.input.id == "policy-signed-descriptor":
            signed_confirm = self.query_one("#policy-signed-confirm", Checkbox)
            signed_confirm.value = False
            signed_confirm.disabled = not bool(
                event.value.strip() and self.query_one("#policy-reason", Input).value.strip()
            )
            self.query_one("#policy-apply-signed", Button).disabled = True
        elif event.input.id in {
            "investigate-target", "investigate-incident", "investigate-call",
            "investigate-minutes", "investigate-model",
        }:
            self._update_investigation_scope()
        elif event.input.id == "behavior-archive-reason":
            self.query_one("#behavior-manage-confirm", Checkbox).value = False
            self._refresh_behavior_actions()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "guard-baseline-confirm":
            self.query_one("#guard-baseline", Button).disabled = not (
                event.value and self._selected_guard_target
            )
        elif event.checkbox.id == "repair-approve-confirm":
            disabled = not (
                event.value and self._selected_repair_approval and self._application_running
            )
            self.query_one("#repair-approve", Button).disabled = disabled
            self.query_one("#repair-reject", Button).disabled = disabled
        elif event.checkbox.id == "behavior-manage-confirm":
            self._refresh_behavior_actions()
        elif event.checkbox.id == "behavior-show-zero-calls":
            self._apply_behavior_filter()
        elif event.checkbox.id == "behavior-show-older":
            self._apply_behavior_filter()
        elif event.checkbox.id == "policy-confirm":
            self.query_one("#policy-apply", Button).disabled = not (
                event.value and self._policy_preview is not None
            )
        elif event.checkbox.id == "policy-release-confirm":
            self.query_one("#policy-release", Button).disabled = not (
                event.value and self._selected_authority_lease
            )
        elif event.checkbox.id == "policy-signed-confirm":
            self.query_one("#policy-apply-signed", Button).disabled = not (
                event.value
                and self.query_one("#policy-signed-descriptor", Input).value.strip()
                and self.query_one("#policy-reason", Input).value.strip()
            )
        elif event.checkbox.id == "policy-override":
            self._policy_preview = None
            self.query_one("#policy-confirm", Checkbox).value = False
            self.query_one("#policy-confirm", Checkbox).disabled = True
            self.query_one("#policy-apply", Button).disabled = True
            self.query_one("#policy-preview-output", Static).update(
                "Override choice changed; preview the guarantee impact again."
            )

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

    @staticmethod
    def _capsule_matches_filter(record: dict[str, Any], expression: str) -> bool:
        tokens = expression.casefold().split()
        if not tokens:
            return True
        searchable = json.dumps(record, default=str).casefold()
        for token in tokens:
            if token == "integrity:invalid":
                if str(record.get("integrity_status") or "").casefold() != "invalid":
                    return False
            elif ":" not in token and token not in searchable:
                return False
            elif ":" in token:
                field, value = token.split(":", 1)
                if field == "integrity":
                    if value not in str(record.get("integrity_status") or "").casefold():
                        return False
                else:
                    aliases = {"incident": "incident_id", "target": "incident_state"}
                    field_value = str(record.get(aliases.get(field, field)) or "").casefold()
                    if value not in field_value and value not in searchable:
                        return False
        return True

    def _apply_incident_capsule_filter(self) -> None:
        expression = self.query_one("#incident-capsule-filter", Input).value
        displayed = [
            record for record in self._capsule_records
            if self._capsule_matches_filter(record, expression)
        ]
        table = self.query_one("#incident-capsule-table", DataTable)
        table.clear()
        for index, record in enumerate(displayed, start=1):
            created = str(record.get("created_at") or "")
            integrity = str(record.get("integrity_status") or "-")
            incident = self._compact_log_text(record.get("incident_id"), limit=12) or "-"
            table.add_row(
                index,
                incident,
                str(record.get("revision") or "-") if integrity != "INVALID" else "-",
                created[:19].replace("T", " ") if created else "-",
                str(record.get("artifact_count") if record.get("artifact_count") is not None else "-"),
                str(record.get("communication_count") if record.get("communication_count") is not None else "-"),
                integrity,
            )
        self.query_one("#incident-capsule-status", Static).update(
            f"Showing {len(displayed)}/{len(self._capsule_records)} capsules | "
            "Verified rows passed hash and revision-chain checks"
        )

    async def refresh_incident_capsules(self) -> None:
        try:
            response = await self._request("incident-capsule-list", limit=200)
        except Exception as exc:
            self._capsule_records = []
            self._selected_capsule = None
            self._incident_artifact_records = []
            self._incident_timeline_records = []
            self.query_one("#incident-capsule-table", DataTable).clear()
            self.query_one("#incident-artifact-table", DataTable).clear()
            self.query_one("#incident-timeline-table", DataTable).clear()
            self.query_one("#incident-timeline-title", Static).update(
                "Correlated persisted timeline"
            )
            self.query_one("#incident-capsule-revision", Input).value = ""
            self.query_one("#incident-capsule-load", Button).disabled = True
            self.query_one("#incident-capsule-status", Static).update(
                f"Incident Capsules unavailable: {type(exc).__name__}: {exc}"
            )
            self.query_one("#incident-capsule-detail-title", Static).update(
                "Select an Incident Capsule"
            )
            self._write_json("#incident-capsule-output", {"error": str(exc)})
            return
        self._capsule_records = [
            dict(item) for item in response.get("capsules", ()) if isinstance(item, dict)
        ]
        self._selected_capsule = None
        self._incident_artifact_records = []
        self._incident_timeline_records = []
        self.query_one("#incident-artifact-table", DataTable).clear()
        self.query_one("#incident-timeline-table", DataTable).clear()
        self.query_one("#incident-timeline-title", Static).update(
            "Correlated persisted timeline"
        )
        self.query_one("#incident-capsule-revision", Input).value = ""
        self.query_one("#incident-capsule-load", Button).disabled = True
        self.query_one("#incident-capsule-detail-title", Static).update(
            "Select an Incident Capsule"
        )
        self._write_json(
            "#incident-capsule-output",
            {"message": "Select an Incident Capsule to inspect its verified envelope."},
        )
        self._apply_incident_capsule_filter()

    async def _select_incident_capsule(
        self,
        record: dict[str, Any],
        *,
        revision: int | None = None,
    ) -> None:
        self._selected_capsule = record
        incident_id = str(record.get("incident_id") or "") or None
        self._set_operator_context(incident=incident_id)
        self._incident_artifact_records = []
        self._incident_timeline_records = []
        self.query_one("#incident-artifact-table", DataTable).clear()
        self.query_one("#incident-timeline-table", DataTable).clear()
        self.query_one("#incident-timeline-title", Static).update(
            "Correlated persisted timeline"
        )
        capsule_id = str(record.get("capsule_id") or "")
        if revision is None:
            self.query_one("#incident-capsule-revision", Input).value = ""
        self.query_one("#incident-capsule-load", Button).disabled = True
        if str(record.get("integrity_status") or "").upper() == "INVALID":
            self.query_one("#incident-capsule-detail-title", Static).update(
                f"Invalid Incident Capsule | {capsule_id}"
            )
            self._write_json("#incident-capsule-output", record)
            return
        try:
            request: dict[str, Any] = {"capsule_id": capsule_id}
            if revision is not None:
                request["revision"] = revision
            response = await self._request("incident-capsule-get", **request)
            envelope = response.get("envelope") or {}
            payload = envelope.get("capsule") or {}
            self.query_one("#incident-capsule-load", Button).disabled = False
            self.query_one("#incident-capsule-detail-title", Static).update(
                f"Verified Incident Capsule | revision {payload.get('revision', '-')}"
            )
            self._write_json("#incident-capsule-output", envelope)
            self._incident_artifact_records = [
                dict(item) for item in payload.get("artifacts", ()) if isinstance(item, dict)
            ]
            artifact_table = self.query_one("#incident-artifact-table", DataTable)
            for index, artifact in enumerate(self._incident_artifact_records, start=1):
                created = str(artifact.get("created_at") or "")
                artifact_table.add_row(
                    index,
                    str(artifact.get("kind") or "-"),
                    created[:19].replace("T", " ") if created else "-",
                    self._compact_log_text(artifact.get("source"), limit=20) or "-",
                    self._compact_log_text(artifact.get("content_sha256"), limit=12) or "-",
                )
            timeline_table = self.query_one("#incident-timeline-table", DataTable)
            try:
                timeline_response = await self._request(
                    "incident-capsule-timeline",
                    incident_id=incident_id or "",
                    limit=200,
                )
                self._incident_timeline_records = [
                    dict(item)
                    for item in timeline_response.get("records", ())
                    if isinstance(item, dict)
                ]
                for index, timeline in enumerate(self._incident_timeline_records, start=1):
                    occurred = str(timeline.get("occurred_at") or "")
                    timeline_table.add_row(
                        index,
                        occurred[:19].replace("T", " ") if occurred else "-",
                        str(timeline.get("severity") or "-"),
                        self._compact_log_text(timeline.get("channel"), limit=14) or "-",
                        self._compact_log_text(timeline.get("target_id"), limit=18) or "-",
                        self._compact_log_text(timeline.get("message"), limit=48) or "-",
                    )
                self.query_one("#incident-timeline-title", Static).update(
                    f"Correlated persisted timeline ({len(self._incident_timeline_records)} records)"
                )
            except Exception as exc:
                self._incident_timeline_records = []
                timeline_table.clear()
                self.query_one("#incident-timeline-title", Static).update(
                    f"Correlated persisted timeline unavailable: {type(exc).__name__}"
                )
        except Exception as exc:
            self.query_one("#incident-capsule-detail-title", Static).update(
                f"Unable to load Incident Capsule | {capsule_id}"
            )
            self._write_json(
                "#incident-capsule-output",
                {"error": f"{type(exc).__name__}: {exc}", "capsule_id": capsule_id},
            )

    async def _select_incident_timeline(self, record: dict[str, Any]) -> None:
        self.query_one("#incident-capsule-detail-title", Static).update(
            f"Persisted evidence record | {record.get('record_id') or '-'}"
        )
        self._write_json("#incident-capsule-output", record)

    async def _select_incident_artifact(self, record: dict[str, Any]) -> None:
        artifact_id = str(record.get("artifact_id") or "")
        try:
            response = await self._request(
                "incident-capsule-artifact",
                artifact_id=artifact_id,
            )
            self.query_one("#incident-capsule-detail-title", Static).update(
                f"Verified side artifact | {record.get('kind') or artifact_id}"
            )
            self._write_json("#incident-capsule-output", response.get("envelope") or response)
        except Exception as exc:
            self._write_json(
                "#incident-capsule-output",
                {"error": f"{type(exc).__name__}: {exc}", "artifact_id": artifact_id},
            )

    async def refresh_logs(self) -> None:
        records: list[dict[str, Any]]
        try:
            response = await self._request("logs", limit=200)
            records = [dict(record) for record in response.get("records", []) if isinstance(record, dict)]
            self._logs_source = "live supervisor"
        except Exception:
            records = self._local_log_records(200)
            self._logs_source = "persisted fallback"
        self._log_records = self._sorted_log_records(records)
        self.query_one("#logs-source-status", Static).update(
            f"Source: {self._logs_source} | loaded {len(self._log_records)}/maximum 200 records | "
            "newest first | refresh with R"
        )
        self._selected_log_record = None
        self.query_one("#logs-investigate", Button).disabled = True
        self.query_one("#logs-related", Button).disabled = True
        self._apply_log_filter()
        self._refresh_investigation_candidates()

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
                "record_id": str(item.record_id),
                "call_id": str(item.call_id) if item.call_id else None,
                "incident_id": str(item.incident_id) if item.incident_id else None,
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
        confirmation = self.query_one("#repair-approve-confirm", Checkbox)
        confirmation.value = False
        confirmation.disabled = True
        for button_id in ("#repair-open-logs", "#repair-open-guard", "#repair-open-investigate"):
            self.query_one(button_id, Button).disabled = True
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

        self._apply_repair_filter()

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

    def _apply_repair_filter(self) -> None:
        expression = self.query_one("#repair-filter", Input).value.strip().casefold()
        self._displayed_repair_records = [
            record for record in self._repair_records
            if not expression or expression in json.dumps(record, default=str).casefold()
        ]
        self._displayed_repair_records.sort(
            key=lambda record: (
                0 if record.get("state") == "WAITING" else 1,
                str(record.get("episode_id") or ""),
                str(record.get("timestamp") or ""),
            )
        )
        table = self.query_one("#repair-table", DataTable)
        table.clear()
        for index, record in enumerate(self._displayed_repair_records, start=1):
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
            self._authority_source = "live supervisor"
        except Exception:
            snapshot = self._local_authority_snapshot()
            self._authority_source = "persisted fallback" if snapshot else "unavailable"
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
        release_confirm = self.query_one("#policy-release-confirm", Checkbox)
        release_confirm.value = False
        release_confirm.disabled = True
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
        release_integrity = (self._last_status or {}).get("release_integrity") or {}
        release_status = str(release_integrity.get("status") or "NOT_CONFIGURED")
        self.query_one("#policy-summary", Static).update(
            f"Overall assurance: {assurance}   Generation: {generation}   "
            f"Violations: {len(violations)}   Runtime: {runtime_match_text}\n"
            f"Effective fingerprint: {fingerprint}\n"
            f"Release integrity (separate from policy authority): {release_status}"
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

    @staticmethod
    def _report_text(value: Any) -> str:
        if isinstance(value, Text):
            return value.plain
        plain = getattr(value, "plain", None)
        return str(plain if plain is not None else value).strip()

    def _build_active_report(self) -> tuple[str, str]:
        tabs = self.query_one(TabbedContent)
        tab_id = str(tabs.active or "console")
        pane = self.query_one(f"#{tab_id}", TabPane)
        generated = datetime.now(timezone.utc)
        sections = [
            "Caretaker Console Report",
            "========================",
            f"Tab: {tab_id}",
            f"Generated (UTC): {generated.isoformat()}",
            f"Data directory: {self.data_directory}",
            self._report_text(self.query_one("#operator-status", Static).render()),
            self._report_text(self.query_one("#data-status", Static).render()),
            self._report_text(self.query_one("#operator-context-label", Static).render()),
        ]

        nonempty_inputs = []
        for widget in pane.query(Input):
            value = widget.value.strip()
            if value:
                nonempty_inputs.append(f"{widget.id or 'input'}: {value}")
        if nonempty_inputs:
            sections.extend(("", "Active inputs", "-------------", *nonempty_inputs))

        visible_summaries = []
        for widget in pane.query(Static):
            if type(widget) is not Static or not widget.display:
                continue
            rendered = self._report_text(widget.render())
            if rendered and rendered not in visible_summaries:
                visible_summaries.append(rendered)
        if visible_summaries:
            sections.extend(("", "On-screen summary", "-----------------", *visible_summaries))

        for table in pane.query(DataTable):
            table_name = table.id or "table"
            sections.extend(("", table_name, "-" * len(table_name)))
            headings = [self._report_text(column.label) for column in table.ordered_columns]
            if headings:
                sections.append(" | ".join(headings))
            row_count = 0
            for row_key in tuple(table.rows):
                try:
                    row = table.get_row(row_key)
                except RowDoesNotExist:
                    continue
                sections.append(" | ".join(self._report_text(cell) for cell in row))
                row_count += 1
            if row_count == 0:
                sections.append("(no rows)")

        for log in pane.query(RichLog):
            log_name = log.id or "details"
            sections.extend(("", log_name, "-" * len(log_name)))
            lines = [line.text.rstrip() for line in log.lines]
            sections.extend(lines or ["(no details)"])

        return tab_id, "\n".join(sections).rstrip() + "\n"

    def _save_active_report(self) -> Path:
        tab_id, report_text = self._build_active_report()
        reports_directory = self.data_directory / "reports"
        reports_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        reports_directory.chmod(0o700)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        path = reports_directory / f"caretaker-{tab_id}-{timestamp}.txt"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as report:
            report.write(report_text)
        return path

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id or ""
        try:
            if button == "save-report":
                path = self._save_active_report()
                self.notify(f"Saved report: {path}", title="Report saved", timeout=10)
                return
            if button == "save-capsule-view":
                if not self._context_incident:
                    raise ValueError("Select or focus an incident before saving the operator view")
                tab_id, report_text = self._build_active_report()
                response = await self._request(
                    "incident-capsule-attach-view",
                    incident_id=self._context_incident,
                    target_id=self._context_target,
                    call_id=self._context_call,
                    tab_id=tab_id,
                    operator_view=report_text,
                )
                artifact = response.get("artifact") or {}
                self.notify(
                    f"Saved operator view artifact {artifact.get('artifact_id', '-')}",
                    title="Incident Capsule updated",
                    timeout=10,
                )
                return
            if button == "incident-capsule-refresh":
                await self.refresh_incident_capsules()
                return
            if button == "incident-capsule-load":
                if self._selected_capsule is None:
                    raise ValueError("Select an Incident Capsule first")
                raw_revision = self.query_one("#incident-capsule-revision", Input).value.strip()
                revision = int(raw_revision) if raw_revision else None
                if revision is not None and revision <= 0:
                    raise ValueError("Revision must be a positive integer")
                await self._select_incident_capsule(
                    self._selected_capsule,
                    revision=revision,
                )
                return
            if button == "context-clear":
                self._set_operator_context()
                return
            if button == "guard-filter-clear":
                self.query_one("#guard-filter", Input).value = ""
                self._apply_guard_filter()
                return
            if button == "behavior-filter-clear":
                self.query_one("#behavior-filter", Input).value = ""
                self._apply_behavior_filter()
                return
            if button.startswith("overview-"):
                target = self._selected_target
                if not target:
                    raise ValueError("Select a target from Overview first")
                if button == "overview-guard":
                    self._selected_guard_target = target
                    self._activate_tab("guard")
                    return
            if button.startswith("repair-open-"):
                record = self._selected_repair_record
                if record is None:
                    raise ValueError("Select a Repair record first")
                target = str(record.get("target_id") or "")
                if button == "repair-open-logs":
                    terms = [f"target:{target}"] if target and target != "-" else []
                    self.query_one("#logs-filter", Input).value = " ".join(terms)
                    self._apply_log_filter()
                    self._activate_tab("logs")
                    return
                if button == "repair-open-guard":
                    self._selected_guard_target = target or None
                    self._activate_tab("guard")
                    return
                if button == "repair-open-investigate":
                    if target and target != "-":
                        self.query_one("#investigate-target", Input).value = target
                    self.query_one("#investigate-objective", Input).value = (
                        f"Investigate Repair episode {record.get('episode_id') or 'unknown'}"
                    )
                    self._activate_tab("investigate")
                    return
                if button == "overview-behavior":
                    self.query_one("#behavior-subject", Input).value = target
                    self._activate_tab("behavior")
                    return
                if button == "overview-logs":
                    self.query_one("#logs-filter", Input).value = f"target:{target}"
                    self._apply_log_filter()
                    self._activate_tab("logs")
                    return
                if button == "overview-investigate":
                    self.query_one("#investigate-target", Input).value = target
                    self.query_one("#investigate-objective", Input).value = f"Investigate operational issues for {target}"
                    self._activate_tab("investigate")
                    return
            if button in {"attention-open", "attention-investigate"}:
                record = self._selected_attention_record
                if record is None:
                    raise ValueError("Select an attention item first")
                target = str(record.get("target_id") or "")
                target = target if target != "-" else ""
                if button == "attention-investigate":
                    if target:
                        self.query_one("#investigate-target", Input).value = target
                    self.query_one("#investigate-objective", Input).value = (
                        f"Investigate {record.get('kind', 'issue')}: {record.get('summary', '')}"
                    )
                    related_logs = [
                        item for item in self._log_records
                        if not target or str(item.get("target_id") or "") == target
                    ]
                    self._refresh_investigation_candidates(related_logs, include_all=True)
                    self._write_json("#investigate-output", record.get("payload") or record)
                    self._activate_tab("investigate")
                    return
                related_tab = str(record.get("related_tab") or "overview")
                if related_tab == "guard" and target:
                    self._selected_guard_target = target
                    guard_record = next(
                        (item for item in self._guard_records if item.get("target_id") == target),
                        None,
                    )
                    if guard_record:
                        self.query_one("#guard-detail-title", Static).update(f"Guard target {target}")
                        self._write_json("#guard-output", guard_record)
                self._activate_tab(related_tab)
                return
            if button == "targets-filter-clear":
                self.query_one("#targets-filter", Input).value = ""
                self._apply_target_filter()
                return
            if button == "logs-filter-clear":
                self.query_one("#logs-filter", Input).value = ""
                self._apply_log_filter()
                self._refresh_investigation_candidates()
                return
            if button.startswith("behavior-"):
                if button == "behavior-refresh":
                    await self.refresh_behavior()
                    return
                if button in {"behavior-capture-function", "behavior-capture-module"}:
                    subject = self.query_one("#behavior-subject", Input).value.strip()
                    if not subject:
                        raise ValueError("Enter a target id or module name first")
                    scope = "function" if button.endswith("function") else "module"
                    response = await self._request(
                        "behavior-capture", scope=scope, subject=subject, calls=50
                    )
                    self._show_behavior_snapshot(response.get("envelope") or {})
                    await self.refresh_behavior()
                    return
                snapshot_id = self._selected_behavior_snapshot
                if button in {
                    "behavior-set-reference",
                    "behavior-compare",
                    "behavior-archive",
                } and not snapshot_id:
                    raise ValueError("Select a behavior snapshot first")
                if button == "behavior-set-reference":
                    selected = self._behavior_record(snapshot_id)
                    if selected is None:
                        raise ValueError("Select a behavior generation first")
                    subject = str(selected.get("subject_key") or "")
                    self._behavior_references[subject] = snapshot_id
                    self._behavior_last_comparison = None
                    self._behavior_view_mode = "detail"
                    self._apply_behavior_filter()
                    self._refresh_behavior_actions()
                    self.query_one("#behavior-detail-title", Static).update(
                        f"Reference set for {subject}"
                    )
                    return
                if button == "behavior-compare":
                    selected = self._behavior_record(snapshot_id)
                    if selected is None:
                        raise ValueError("Select a behavior generation first")
                    subject = str(selected.get("subject_key") or "")
                    reference_id = self._behavior_references.get(subject)
                    if not reference_id:
                        raise ValueError("No reference is available for the selected subject")
                    if reference_id == snapshot_id:
                        raise ValueError("Select another generation for this subject to compare")
                    response = await self._request(
                        "behavior-compare",
                        snapshot_a_id=reference_id,
                        snapshot_b_id=snapshot_id,
                    )
                    comparison = dict(response.get("comparison") or {})
                    reference = self._behavior_record(reference_id) or {}
                    for suffix, record in (("a", reference), ("b", selected)):
                        profile = record.get("profile") or {}
                        provenance = profile.get("sampling_provenance") or {}
                        comparison[f"generation_coverage_{suffix}"] = {
                            "calls": int(profile.get("coverage_call_count", profile.get("call_count")) or 0),
                            "epochs": int(profile.get("coverage_snapshot_count") or record.get("snapshot_count") or 1),
                            "target": int(provenance.get("statistics_target") or 0),
                            "gaps": int(profile.get("coverage_gap_count") or 0),
                        }
                    self._show_behavior_comparison(comparison)
                    return
                if button == "behavior-assess-comparison":
                    if self._behavior_last_comparison is None:
                        raise ValueError("Run a behavior comparison before requesting an LLM opinion")
                    model = self.query_one("#behavior-model", Input).value.strip()
                    if not model:
                        raise ValueError("Enter an Ollama model for the advisory opinion")
                    response = await self._request(
                        "behavior-assess",
                        comparison=self._behavior_last_comparison,
                        model=model,
                        objective="Assess whether the observed behavior changes are significant, suspicious, or plausibly benign",
                    )
                    self._write_json("#behavior-output", response.get("assessment") or response)
                    return
                if button == "behavior-assess-history":
                    model = self.query_one("#behavior-model", Input).value.strip()
                    if not model:
                        raise ValueError("Enter an Ollama model for the advisory history analysis")
                    response = await self._request(
                        "behavior-assess-history",
                        model=model,
                        objective="Assess overall behavior history and identify meaningful code-generation or runtime behavior changes",
                    )
                    self._write_json("#behavior-output", response.get("assessment") or response)
                    return
                if button == "behavior-archive":
                    if not self.query_one("#behavior-manage-confirm", Checkbox).value:
                        raise ValueError("Confirm that you intend to archive the selected generation")
                    reason = self.query_one("#behavior-archive-reason", Input).value.strip()
                    if not reason:
                        raise ValueError("Enter a reason for archiving the selected generation")
                    selected = self._behavior_record(snapshot_id)
                    if selected is None:
                        raise ValueError("Select a behavior generation first")
                    subject_key = str(selected.get("subject_key") or "")
                    generation_id = str(selected.get("generation_id") or "")
                    response = await self._request(
                        "behavior-archive",
                        subject_key=subject_key,
                        generation_id=generation_id,
                        reason=reason,
                    )
                    self._behavior_references = {
                        subject: reference_id
                        for subject, reference_id in self._behavior_references.items()
                        if not (
                            subject == subject_key
                            and str((self._behavior_record(reference_id) or {}).get("generation_id") or "")
                            == generation_id
                        )
                    }
                    self._selected_behavior_snapshot = None
                    self.query_one("#behavior-archive-reason", Input).value = ""
                    self._write_json("#behavior-output", response)
                    await self.refresh_behavior()
                    return
            if button.startswith("guard-"):
                if button == "guard-refresh":
                    await self.refresh_guard()
                    return
                target = self._selected_guard_target
                if not target:
                    raise ValueError("Select a Guard target from the operational status table first")
                if button == "guard-open-behavior":
                    self.query_one("#behavior-subject", Input).value = target
                    self._activate_tab("behavior")
                    return
                if button == "guard-open-logs":
                    self.query_one("#logs-filter", Input).value = f"target:{target} channel:guard"
                    self._apply_log_filter()
                    self._activate_tab("logs")
                    return
                if button == "guard-open-investigate":
                    self.query_one("#investigate-target", Input).value = target
                    self.query_one("#investigate-objective", Input).value = f"Investigate Guard findings for {target}"
                    self._activate_tab("investigate")
                    return
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
                if button == "guard-baseline":
                    self.query_one("#guard-baseline-confirm", Checkbox).value = False
                    self.query_one("#guard-baseline", Button).disabled = True
                    await self.refresh_guard()
                return
            if button == "logs-investigate":
                record = self._selected_log_record
                if record is None:
                    raise ValueError("Select a log record first")
                target = str(record.get("target_id") or "")
                channel = str(record.get("channel") or "")
                logger = str(record.get("logger") or "")
                terms = [f"target:{target}"] if target else []
                if channel:
                    terms.append(f"channel:{channel}")
                if not target and logger:
                    terms.append(f"logger:{logger}")
                expression = " ".join(terms)
                self.query_one("#logs-filter", Input).value = expression
                self._apply_log_filter()
                self._refresh_investigation_candidates(
                    self._displayed_log_records,
                    include_all=True,
                )
                self._selected_investigation_record = record
                if target:
                    self.query_one("#investigate-target", Input).value = target
                if record.get("incident_id"):
                    self.query_one("#investigate-incident", Input).value = str(record["incident_id"])
                if record.get("call_id"):
                    self.query_one("#investigate-call", Input).value = str(record["call_id"])
                message = self._compact_log_text(record.get("message"), limit=100)
                self.query_one("#investigate-objective", Input).value = (
                    f"Investigate evidence similar to: {message}"
                )
                self.query_one("#investigate-detail-title", Static).update(
                    f"Context from Logs | {channel or '-'} | {target or logger or 'unscoped'}"
                )
                self._write_json("#investigate-output", record)
                self._activate_tab("investigate")
                return
            if button == "logs-related":
                record = self._selected_log_record
                if record is None:
                    raise ValueError("Select a log record first")
                channel = str(record.get("channel") or "").upper()
                target = str(record.get("target_id") or "")
                if channel == "GUARD" and target:
                    self._selected_guard_target = target
                    guard_record = next(
                        (item for item in self._guard_records if item["target_id"] == target),
                        {"target_id": target, "message": "Select a Guard action for live details"},
                    )
                    self.query_one("#guard-detail-title", Static).update(f"Guard target {target}")
                    self._write_json("#guard-output", guard_record)
                    self._activate_tab("guard")
                elif channel == "REPAIR":
                    self._activate_tab("repair")
                elif channel in {"AUDIT", "INTEGRITY"}:
                    self._activate_tab("policy")
                elif target:
                    self.query_one("#behavior-subject", Input).value = target
                    self._activate_tab("behavior")
                else:
                    self._activate_tab("investigate")
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
                if not self.query_one("#repair-approve-confirm", Checkbox).value:
                    raise ValueError("Review the evidence and confirm the Repair decision first")
                if button == "repair-approve":
                    response = await self._request("runtime-repair-approve", episode_id=episode)
                else:
                    reason = self.query_one("#repair-reason", Input).value.strip()
                    if not reason:
                        raise ValueError("Rejecting a Repair candidate requires an operator reason")
                    response = await self._request(
                        "runtime-repair-reject",
                        episode_id=episode,
                        reason=reason,
                    )
                self._write_json("#repair-output", response)
                await self.refresh_status()
                await self.refresh_targets()
                await self.refresh_repair()
                return
            if button == "policy-refresh":
                await self.refresh_authority()
                return
            if button in {"policy-preset-approval", "policy-preset-automatic"}:
                self.query_one("#policy-path", Input).value = "repair.authority"
                self.query_one("#policy-value", Input).value = (
                    "REQUIRE_OPERATOR_APPROVAL"
                    if button == "policy-preset-approval"
                    else "AUTOMATIC_ELIGIBLE_REPAIRS"
                )
                if self._context_target:
                    self.query_one("#policy-target", Input).value = self._context_target
                self.query_one("#policy-preview-output", Static).update(
                    "Preset loaded. Confirm target scope, duration, and reason, then Preview change."
                )
                return
            if button == "policy-preview":
                path = self.query_one("#policy-path", Input).value.strip()
                target = self.query_one("#policy-target", Input).value.strip()
                reason = self.query_one("#policy-reason", Input).value.strip()
                if not path or not reason:
                    raise ValueError("Preview requires a policy path and incident/operator reason")
                if path.startswith("repair.") and not target:
                    raise ValueError("Temporary repair policy changes require a target id or glob")
                preview = {
                    "path": path,
                    "value": self._parse_policy_value(self.query_one("#policy-value", Input).value),
                    "target": target or None,
                    "duration_seconds": int(self.query_one("#policy-duration", Input).value.strip() or "3600"),
                    "reason": reason,
                    "override_constraints": self.query_one("#policy-override", Checkbox).value,
                }
                self._policy_preview = preview
                impact = (
                    "WARNING: explicit override may violate a higher-authority guarantee."
                    if preview["override_constraints"] else
                    "Higher-authority constraints remain enforced; the supervisor may reject this lease."
                )
                self.query_one("#policy-preview-output", Static).update(
                    f"Temporary change: {path} = {preview['value']} | target={target or 'GLOBAL'} | "
                    f"expires after {preview['duration_seconds']}s | {impact}"
                )
                self.query_one("#policy-confirm", Checkbox).disabled = False
                return
            if button == "policy-apply":
                if self._policy_preview is None:
                    raise ValueError("Preview and confirm the policy change first")
                preview = self._policy_preview
                response = await self._request(
                    "authority-lease-acquire",
                    **preview,
                )
                self._write_json("#policy-output", response)
                await self.refresh_authority()
                await self.refresh_status()
                await self.refresh_targets()
                self._policy_preview = None
                self.query_one("#policy-confirm", Checkbox).value = False
                self.query_one("#policy-confirm", Checkbox).disabled = True
                self.query_one("#policy-apply", Button).disabled = True
                return
            if button == "policy-apply-signed":
                descriptor = self.query_one("#policy-signed-descriptor", Input).value.strip()
                if not descriptor:
                    raise ValueError(
                        "Enter a signed lease descriptor filename from policy/runtime-leases/"
                    )
                reason = self.query_one("#policy-reason", Input).value.strip()
                if not reason:
                    raise ValueError("Applying a signed lease requires an incident/operator reason")
                if not self.query_one("#policy-signed-confirm", Checkbox).value:
                    raise ValueError("Review and confirm the signed lease scope first")
                response = await self._request(
                    "authority-lease-acquire-signed",
                    descriptor=descriptor,
                    reason=reason,
                )
                self._write_json("#policy-output", response)
                await self.refresh_authority()
                await self.refresh_status()
                await self.refresh_targets()
                return
            if button == "policy-release":
                if not self._selected_authority_lease:
                    raise ValueError("Select a runtime policy lease first")
                if not self.query_one("#policy-release-confirm", Checkbox).value:
                    raise ValueError("Confirm release of the selected runtime policy lease first")
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
                incident = self.query_one("#investigate-incident", Input).value.strip()
                call = self.query_one("#investigate-call", Input).value.strip()
                minutes = max(1, min(int(self.query_one("#investigate-minutes", Input).value.strip() or "15"), 1440))
                model = self.query_one("#investigate-model", Input).value.strip()
                objective = self.query_one("#investigate-objective", Input).value.strip()
                response = await self._request(
                    "investigate",
                    target=target or None,
                    call_id=call or None,
                    incident_id=incident or None,
                    model=model or None,
                    objective=objective or "Investigate the current Caretaker incident",
                    minutes=minutes,
                )
                output = self.query_one("#investigate-output", RichLog)
                output.clear()
                output.write(
                    f"[b]Investigation result[/b] provider={response.get('provider', 'deterministic')}\n"
                    f"Evidence hash: {response.get('evidence_hash', '-')}\n"
                    f"Omitted records: {response.get('omitted_record_count', 0)}\n"
                    "This assessment is advisory and cannot approve Repair or override policy."
                )
                assessment = response.get("assessment") or {}
                output.write("\n[b]Assessment[/b]")
                output.write(json.dumps(assessment, indent=2, sort_keys=True, default=str))
                return
        except Exception as exc:
            output = "#guard-output" if button.startswith("guard-") else "#repair-output"
            if button.startswith("behavior-"):
                output = "#behavior-output"
            elif button == "investigate-run":
                output = "#investigate-output"
            elif button.startswith("logs-"):
                output = "#logs-output"
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
