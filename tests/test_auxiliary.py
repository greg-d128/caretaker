from caretaker import AuxiliaryFunctionManager, AuxiliaryRegistry


def test_auxiliary_validator_is_sandboxed_and_registered() -> None:
    registry = AuxiliaryRegistry()
    manager = AuxiliaryFunctionManager(registry)
    source = """
def validate_invoice(value):
    return (
        isinstance(value, dict)
        and set(value) == {"subtotal", "tax", "total"}
        and value["subtotal"] >= 0
        and value["tax"] >= 0
        and value["total"] == value["subtotal"] + value["tax"]
    )
"""
    artifact = manager.install_output_validator(
        target_id="tests:invoice",
        source=source,
        entrypoint="validate_invoice",
        valid_examples=({"subtotal": 10, "tax": 2, "total": 12},),
        invalid_examples=(
            {"subtotal": 10, "tax": 2, "total": 13},
            {"unexpected": 1},
        ),
    )
    validator = registry.resolve(artifact.registry_id)
    assert validator({"subtotal": 5, "tax": 1, "total": 6}) is True
    assert validator({"subtotal": 5, "tax": 1, "total": 7}) is False
