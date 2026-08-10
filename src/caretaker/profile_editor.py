from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
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

from .authority import ConstraintOperator, PolicyConstraint, PolicySetting
from .profiles import (
    CURRENT_POLICY_SURFACE_VERSION,
    OFFICIAL_PROFILE_SIGNING_ROLE,
    compare_profiles,
    create_profile,
    format_comparison_text,
    load_profile,
    parse_json_value,
    policy_capabilities_since,
    profile_identity,
    profile_summary,
    write_profile,
)


class ProfileEditorApp(App):
    TITLE = "Caretaker Profile Editor"
    SUB_TITLE = "Create, continue, review, and compare policy-authority profiles"

    CSS = """
    Screen { layout: vertical; }
    #profile-status {
        height: 4;
        padding: 1 2;
        border-bottom: solid $accent;
    }
    TabbedContent { height: 1fr; }
    .form-row { height: 4; padding: 0 1; align-vertical: middle; }
    .form-row Input { width: 1fr; min-width: 18; margin-right: 1; }
    .form-row Checkbox { width: auto; margin-right: 2; }
    .form-row Button { width: auto; min-width: 12; margin-left: 1; }
    .help { height: auto; padding: 1 2; color: $text-muted; }
    DataTable, RichLog { height: 1fr; border: solid $surface-lighten-2; }
    #identity-description { height: 5; }
    #review-actions { height: 4; padding: 0 1; align-vertical: middle; }
    #review-actions Input { width: 1fr; min-width: 30; }
    #review-actions Button { width: auto; min-width: 14; margin-left: 1; }
    """

    BINDINGS = [("q", "quit", "Quit"), ("ctrl+s", "save_profile", "Save")]

    def __init__(
        self,
        *,
        profile_path: Path | None = None,
        output_path: Path | None = None,
    ) -> None:
        super().__init__()
        self.profile_path = profile_path.expanduser().resolve() if profile_path else None
        self.output_path = output_path.expanduser().resolve() if output_path else None
        self._base_layer = None
        self._settings: list[PolicySetting] = []
        self._constraints: list[PolicyConstraint] = []
        self._selected_setting: int | None = None
        self._selected_constraint: int | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(
            f"Policy surface {CURRENT_POLICY_SURFACE_VERSION}. "
            "Profiles are ordinary framework authority layers; signing and selection pinning remain separate operations.",
            id="profile-status",
        )
        with TabbedContent(initial="identity"):
            with TabPane("Identity", id="identity"):
                yield Static(
                    "Lineage is stable across versions. Version identifies a revision within that lineage. "
                    "Opening an existing profile starts a continuation by default.",
                    classes="help",
                )
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="Stable lineage, e.g. acme.production", id="profile-lineage")
                    yield Input(placeholder="Descriptive name, e.g. Acme Production", id="profile-name")
                    yield Input(value="1", placeholder="Version", id="profile-version")
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="Authority id", id="profile-authority")
                    yield Input(placeholder="Minimum Caretaker version", id="profile-minimum")
                    yield Input(placeholder="Tested through Caretaker version", id="profile-tested")
                with Horizontal(classes="form-row"):
                    yield Input(
                        placeholder=f"Signer role (official profiles: {OFFICIAL_PROFILE_SIGNING_ROLE})",
                        id="profile-signer-role",
                    )
                    yield Input(placeholder="Origin, e.g. organization name", id="profile-origin")
                    yield Checkbox("Require complete policy surface", id="profile-strict-surface")
                    yield Checkbox("Require review for exact Caretaker version", id="profile-strict-version")
                yield Static(
                    "Complete-surface mode refuses newly introduced policy capability until the lineage is reviewed. "
                    "Exact-version mode additionally requires a new review for every Caretaker version.",
                    classes="help",
                )
                yield Input(
                    placeholder="Profile purpose and intended operating posture",
                    id="identity-description",
                )
                yield Static(
                    "The editor writes canonical unsigned profile content. Sign canonical output using the appropriate "
                    "external profile-signing authority; Caretaker intentionally has no private-key signing interface.",
                    classes="help",
                )
            with TabPane("Settings", id="settings"):
                yield Static(
                    "Settings choose behavior. JSON values are parsed automatically; plain text remains a string.",
                    classes="help",
                )
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="Policy path, e.g. repair.authority", id="setting-path")
                    yield Input(placeholder='Value, e.g. "REQUIRE_OPERATOR_APPROVAL"', id="setting-value")
                    yield Input(placeholder="Target/glob (optional)", id="setting-target")
                with Horizontal(classes="form-row"):
                    yield Checkbox("Explicit constraint override", id="setting-override")
                    yield Input(placeholder="Reason (required for override)", id="setting-reason")
                    yield Button("Add / replace", id="setting-add", variant="primary")
                    yield Button("Remove selected", id="setting-remove", disabled=True)
                table = DataTable(id="settings-table")
                table.cursor_type = "row"
                table.add_columns("#", "Path", "Target", "Value", "Override")
                yield table
            with TabPane("Constraints", id="constraints"):
                yield Static(
                    "Constraints are guarantees lower authority must satisfy unless it explicitly overrides them.",
                    classes="help",
                )
                with Horizontal(classes="form-row"):
                    yield Input(placeholder="Policy path", id="constraint-path")
                    yield Input(
                        placeholder="Operator: exact, allowed-values, required-true, ...",
                        id="constraint-operator",
                    )
                    yield Input(placeholder="Value as JSON (if applicable)", id="constraint-value")
                    yield Input(placeholder="Target/glob (optional)", id="constraint-target")
                    yield Button("Add / replace", id="constraint-add", variant="primary")
                    yield Button("Remove selected", id="constraint-remove", disabled=True)
                table = DataTable(id="constraints-table")
                table.cursor_type = "row"
                table.add_columns("#", "Path", "Target", "Operator", "Value")
                yield table
            with TabPane("Review", id="review"):
                yield Static(
                    "Review lineage, semantic differences, and newly introduced policy-controlled capabilities before signing or pinning.",
                    classes="help",
                )
                with Horizontal(id="review-actions"):
                    yield Input(
                        placeholder="Optional policy/profile to compare against",
                        id="compare-path",
                    )
                    yield Button("Compare", id="compare-run")
                    yield Button("Coverage", id="coverage-run")
                    yield Button("Preview", id="preview-run")
                    yield Button("Save", id="profile-save", variant="success")
                yield RichLog(id="review-output", wrap=True, markup=False)
        yield Footer()

    async def on_mount(self) -> None:
        if self.profile_path:
            try:
                self._load_existing(self.profile_path)
            except Exception as exc:
                self._write_review(f"Unable to load {self.profile_path}: {type(exc).__name__}: {exc}")
        else:
            self.query_one("#profile-authority", Input).value = "local-profile"
            self.query_one("#profile-tested", Input).value = self._caretaker_version()
            self._write_review(self._coverage_text(0))
        self._refresh_tables()

    @staticmethod
    def _caretaker_version() -> str:
        try:
            import caretaker

            return str(caretaker.__version__)
        except Exception:
            return ""

    def _load_existing(self, path: Path) -> None:
        layer = load_profile(path)
        identity = profile_identity(layer, required=True)
        assert identity is not None
        self._base_layer = layer
        self._settings = list(layer.settings)
        self._constraints = list(layer.constraints)
        self.query_one("#profile-lineage", Input).value = identity.lineage
        self.query_one("#profile-name", Input).value = identity.name
        self.query_one("#profile-version", Input).value = str(identity.version + 1)
        self.query_one("#profile-authority", Input).value = layer.authority_id
        self.query_one("#profile-minimum", Input).value = identity.caretaker_minimum or ""
        self.query_one("#profile-tested", Input).value = self._caretaker_version() or identity.caretaker_tested_through or ""
        self.query_one("#profile-signer-role", Input).value = identity.signer_role or ""
        self.query_one("#profile-origin", Input).value = identity.origin or ""
        self.query_one("#profile-strict-surface", Checkbox).value = identity.require_complete_surface
        self.query_one("#profile-strict-version", Checkbox).value = identity.require_current_caretaker_version
        self.query_one("#identity-description", Input).value = identity.description or ""
        self.query_one("#compare-path", Input).value = str(path)
        self.query_one("#profile-status", Static).update(
            f"Continuing {identity.display_name}; draft defaults to v{identity.version + 1}. "
            f"Policy surface advances from {identity.policy_surface_version} to {CURRENT_POLICY_SURFACE_VERSION}."
        )
        self._write_review(self._coverage_text(identity.policy_surface_version))

    def _coverage_text(self, previous_surface: int) -> str:
        capabilities = policy_capabilities_since(previous_surface)
        if not capabilities:
            return (
                f"Policy surface {CURRENT_POLICY_SURFACE_VERSION}: no newly introduced capabilities "
                "require review relative to the selected profile."
            )
        lines = [
            f"Policy surface {CURRENT_POLICY_SURFACE_VERSION}: {len(capabilities)} capability decision(s) "
            "were introduced after the selected profile:"
        ]
        for item in capabilities:
            lines.extend(
                [
                    "",
                    f"{item.capability_id} - {item.title}",
                    f"Introduced: {item.introduced_in}",
                    item.description,
                    "Review: " + item.review_note,
                ]
            )
        return "\n".join(lines)

    def _build_layer(self):
        lineage = self.query_one("#profile-lineage", Input).value.strip()
        name = self.query_one("#profile-name", Input).value.strip()
        authority_id = self.query_one("#profile-authority", Input).value.strip()
        if not lineage or not name or not authority_id:
            raise ValueError("Lineage, descriptive name, and authority id are required")
        version = int(self.query_one("#profile-version", Input).value.strip())
        minimum = self.query_one("#profile-minimum", Input).value.strip() or None
        tested = self.query_one("#profile-tested", Input).value.strip() or None
        signer_role = self.query_one("#profile-signer-role", Input).value.strip() or None
        origin = self.query_one("#profile-origin", Input).value.strip() or None
        description = self.query_one("#identity-description", Input).value.strip() or None
        strict = self.query_one("#profile-strict-surface", Checkbox).value
        strict_version = self.query_one("#profile-strict-version", Checkbox).value
        supersedes = None
        based_on = None
        if self._base_layer is not None:
            base_identity = profile_identity(self._base_layer, required=True)
            assert base_identity is not None
            if lineage == base_identity.lineage:
                supersedes = self._base_layer
            else:
                based_on = self._base_layer
        return create_profile(
            authority_id=authority_id,
            lineage=lineage,
            name=name,
            version=version,
            description=description,
            caretaker_minimum=minimum,
            caretaker_tested_through=tested,
            signer_role=signer_role,
            require_complete_surface=strict,
            require_current_caretaker_version=strict_version,
            origin=origin,
            settings=tuple(self._settings),
            constraints=tuple(self._constraints),
            supersedes=supersedes,
            based_on=based_on,
        )

    def _refresh_tables(self) -> None:
        settings = self.query_one("#settings-table", DataTable)
        settings.clear()
        for index, item in enumerate(self._settings, start=1):
            settings.add_row(
                index,
                item.path,
                item.target or "-",
                json.dumps(item.value, sort_keys=True, default=str),
                "yes" if item.override_constraints else "no",
            )
        constraints = self.query_one("#constraints-table", DataTable)
        constraints.clear()
        for index, item in enumerate(self._constraints, start=1):
            constraints.add_row(
                index,
                item.path,
                item.target or "-",
                item.operator.value,
                json.dumps(item.value, sort_keys=True, default=str),
            )
        self._selected_setting = None
        self._selected_constraint = None
        self.query_one("#setting-remove", Button).disabled = True
        self.query_one("#constraint-remove", Button).disabled = True

    def _write_review(self, text: str) -> None:
        output = self.query_one("#review-output", RichLog)
        output.clear()
        output.write(text)

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row = event.data_table.get_row(event.row_key)
        if not row:
            return
        try:
            index = int(row[0]) - 1
        except (TypeError, ValueError):
            return
        if event.data_table.id == "settings-table" and 0 <= index < len(self._settings):
            self._selected_setting = index
            item = self._settings[index]
            self.query_one("#setting-path", Input).value = item.path
            self.query_one("#setting-value", Input).value = json.dumps(item.value, default=str)
            self.query_one("#setting-target", Input).value = item.target or ""
            self.query_one("#setting-override", Checkbox).value = item.override_constraints
            self.query_one("#setting-reason", Input).value = item.reason or ""
            self.query_one("#setting-remove", Button).disabled = False
        elif event.data_table.id == "constraints-table" and 0 <= index < len(self._constraints):
            self._selected_constraint = index
            item = self._constraints[index]
            self.query_one("#constraint-path", Input).value = item.path
            self.query_one("#constraint-operator", Input).value = item.operator.value
            self.query_one("#constraint-value", Input).value = (
                "" if item.value is None else json.dumps(item.value, default=str)
            )
            self.query_one("#constraint-target", Input).value = item.target or ""
            self.query_one("#constraint-remove", Button).disabled = False

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id or ""
        try:
            if button == "setting-add":
                path = self.query_one("#setting-path", Input).value.strip()
                value = parse_json_value(self.query_one("#setting-value", Input).value)
                target = self.query_one("#setting-target", Input).value.strip() or None
                override = self.query_one("#setting-override", Checkbox).value
                reason = self.query_one("#setting-reason", Input).value.strip() or None
                item = PolicySetting(path, value, target, override, reason)
                key = (item.path, item.target)
                self._settings = [existing for existing in self._settings if (existing.path, existing.target) != key]
                self._settings.append(item)
                self._settings.sort(key=lambda value: (value.path, value.target or ""))
                self._refresh_tables()
                return
            if button == "setting-remove":
                if self._selected_setting is not None:
                    del self._settings[self._selected_setting]
                    self._refresh_tables()
                return
            if button == "constraint-add":
                path = self.query_one("#constraint-path", Input).value.strip()
                operator = ConstraintOperator(
                    self.query_one("#constraint-operator", Input).value.strip().casefold()
                )
                raw = self.query_one("#constraint-value", Input).value.strip()
                value: Any = None if not raw else parse_json_value(raw)
                target = self.query_one("#constraint-target", Input).value.strip() or None
                item = PolicyConstraint(path, operator, value, target)
                key = (item.path, item.target, item.operator)
                self._constraints = [
                    existing
                    for existing in self._constraints
                    if (existing.path, existing.target, existing.operator) != key
                ]
                self._constraints.append(item)
                self._constraints.sort(
                    key=lambda value: (value.path, value.target or "", value.operator.value)
                )
                self._refresh_tables()
                return
            if button == "constraint-remove":
                if self._selected_constraint is not None:
                    del self._constraints[self._selected_constraint]
                    self._refresh_tables()
                return
            if button == "coverage-run":
                previous_surface = 0
                if self._base_layer is not None:
                    identity = profile_identity(self._base_layer, required=True)
                    assert identity is not None
                    previous_surface = identity.policy_surface_version
                self._write_review(self._coverage_text(previous_surface))
                return
            if button == "preview-run":
                layer = self._build_layer()
                self._write_review(json.dumps(profile_summary(layer), indent=2, sort_keys=True, default=str))
                return
            if button == "compare-run":
                draft = self._build_layer()
                compare_path = self.query_one("#compare-path", Input).value.strip()
                base = load_profile(compare_path) if compare_path else self._base_layer
                if base is None:
                    raise ValueError("Enter a profile to compare, or start by opening an existing profile")
                self._write_review(format_comparison_text(compare_profiles(base, draft)))
                return
            if button == "profile-save":
                await self.action_save_profile()
                return
        except Exception as exc:
            self._write_review(f"{type(exc).__name__}: {exc}")

    async def action_save_profile(self) -> None:
        try:
            layer = self._build_layer()
            path = self.output_path
            if path is None:
                if self.profile_path is not None:
                    identity = profile_identity(layer, required=True)
                    assert identity is not None
                    path = self.profile_path.with_name(
                        f"{identity.lineage.replace('.', '-')}-v{identity.version}.json"
                    )
                else:
                    identity = profile_identity(layer, required=True)
                    assert identity is not None
                    path = Path(f"{identity.lineage.replace('.', '-')}-v{identity.version}.json").resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists() and path != self.profile_path:
                raise FileExistsError(f"Refusing to overwrite existing profile {path}")
            write_profile(path, layer)
            self.output_path = path
            self._write_review(
                f"Saved canonical profile:\n  {path}\n\n"
                f"Fingerprint:\n  {layer.fingerprint}\n\n"
                "The file is not signed by the editor. Sign the canonical bytes using the "
                "profile's authorized external signing role, then create/preserve a deployment "
                "pin to the exact fingerprint where selection integrity is required."
            )
        except Exception as exc:
            self._write_review(f"{type(exc).__name__}: {exc}")


def run_editor(
    *,
    profile_path: Path | None = None,
    output_path: Path | None = None,
) -> None:
    ProfileEditorApp(profile_path=profile_path, output_path=output_path).run()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="caretaker-profile-editor")
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    run_editor(profile_path=args.profile, output_path=args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
