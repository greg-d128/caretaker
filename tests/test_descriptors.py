from __future__ import annotations

from caretaker import RepairEngine, RepairPolicy, repair


def test_repair_preserves_supported_descriptors() -> None:
    engine = RepairEngine()

    class Example:
        def __init__(self, value: int) -> None:
            self.value = value

        @repair(engine=engine, policy=RepairPolicy(), target_id="test.descriptor.static")
        @staticmethod
        def static(value: int) -> int:
            return value + 1

        @repair(engine=engine, policy=RepairPolicy(), target_id="test.descriptor.class")
        @classmethod
        def class_value(cls, value: int) -> int:
            return value + len(cls.__name__)

        @repair(engine=engine, policy=RepairPolicy(), target_id="test.descriptor.property")
        @property
        def doubled(self) -> int:
            return self.value * 2

    assert isinstance(Example.__dict__["static"], staticmethod)
    assert isinstance(Example.__dict__["class_value"], classmethod)
    assert isinstance(Example.__dict__["doubled"], property)
    assert Example.static(3) == 4
    assert Example.class_value(3) == 10
    assert Example(4).doubled == 8


def test_repair_still_supports_descriptor_inside_decorator() -> None:
    engine = RepairEngine()

    class Example:
        @staticmethod
        @repair(engine=engine, policy=RepairPolicy(), target_id="test.descriptor.inner")
        def static(value: int) -> int:
            return value

    assert Example.static(7) == 7
