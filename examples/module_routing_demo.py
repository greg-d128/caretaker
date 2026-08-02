"""Demonstrate pre-import module variant selection and quarantine.

The example uses temporary source files. Real deployments should use signed,
reviewed variants and normally apply changed routes through an external process
restart.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from caretaker import ModuleRoutePolicy, ModuleRouter, ModuleVariant


def main() -> None:
    with TemporaryDirectory() as directory:
        root = Path(directory)
        primary = root / "example_dependency.py"
        fallback = root / "example_dependency_fallback.py"
        primary.write_text("VALUE = 'primary'\n", encoding="utf-8")
        fallback.write_text("VALUE = 'fallback'\n", encoding="utf-8")

        router = ModuleRouter()
        router.register_variant(
            ModuleVariant(
                variant_id="example-primary",
                import_name="example_dependency",
                distribution_name=None,
                distribution_version="1",
                source_location=str(primary),
                source_hash=None,
                integrity_state="SIGNED_RELEASE",
                behavior_baseline_id=None,
                priority=10,
            )
        )
        router.register_variant(
            ModuleVariant(
                variant_id="example-fallback",
                import_name="example_dependency",
                distribution_name=None,
                distribution_version="0",
                source_location=str(fallback),
                source_hash=None,
                integrity_state="SIGNED_RELEASE",
                behavior_baseline_id=None,
                priority=5,
            )
        )
        router.register_policy(
            ModuleRoutePolicy(
                import_name="example_dependency",
                preferred_variant_id="example-primary",
                fallback_variant_ids=("example-fallback",),
                require_accepted_baseline=False,
            )
        )

        selected, decision = router.select("example_dependency")
        print(selected.variant_id, decision.action)

        router.quarantine("example-primary")
        selected, decision = router.select("example_dependency")
        print(selected.variant_id, decision.action)


if __name__ == "__main__":
    main()
