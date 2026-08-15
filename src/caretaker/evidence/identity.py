from __future__ import annotations

import hashlib
import importlib.metadata
import inspect
import json
import marshal
import sys
from functools import lru_cache
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

from .models import CodeIdentity, DependencyIdentity


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_path(path: str | Path | None) -> str | None:
    if path is None:
        return None
    candidate = Path(path)
    try:
        stat = candidate.stat()
        return _cached_path_hash(str(candidate), stat.st_mtime_ns, stat.st_size)
    except (OSError, ValueError):
        return None


@lru_cache(maxsize=4096)
def _cached_path_hash(path: str, mtime_ns: int, size: int) -> str | None:
    try:
        return _sha256_bytes(Path(path).read_bytes())
    except OSError:
        return None


@lru_cache(maxsize=2048)
def _distribution_for_module(module_name: str) -> tuple[str | None, str | None]:
    top_level = module_name.split(".", 1)[0]
    try:
        mapping = importlib.metadata.packages_distributions()
        distributions = mapping.get(top_level, ())
    except Exception:
        distributions = ()
    if not distributions:
        return None, None
    name = sorted(distributions)[0]
    try:
        return name, importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return name, None


def function_source_hash(function: Callable[..., Any]) -> str | None:
    """Hash only the inspected function source, avoiding unrelated module-file edits."""
    try:
        source = inspect.getsource(function)
    except (OSError, TypeError):
        return None
    return _sha256_bytes(source.encode("utf-8"))


def _code_hash(function: Callable[..., Any]) -> str | None:
    code = getattr(function, "__code__", None)
    if code is None:
        return None
    try:
        return _sha256_bytes(marshal.dumps(code))
    except (TypeError, ValueError):
        payload = {
            "co_code": code.co_code.hex(),
            "co_consts": repr(code.co_consts),
            "co_names": code.co_names,
            "co_varnames": code.co_varnames,
        }
        return _sha256_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))


def identify_module(module: ModuleType | str) -> CodeIdentity:
    if isinstance(module, str):
        module_name = module
        loaded = sys.modules.get(module_name)
    else:
        loaded = module
        module_name = module.__name__
    distribution_name, distribution_version = _distribution_for_module(module_name)
    source_path = getattr(loaded, "__file__", None) if loaded is not None else None
    suffix = Path(source_path).suffix.lower() if source_path else ""
    native_extension = suffix in {".so", ".pyd", ".dll", ".dylib"}
    loader = getattr(getattr(loaded, "__spec__", None), "loader", None) if loaded else None
    return CodeIdentity(
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        module_name=module_name,
        source_path=source_path,
        source_hash=_hash_path(source_path),
        native_extension=native_extension,
        loader_name=(f"{type(loader).__module__}.{type(loader).__qualname__}" if loader else None),
    )


def identify_function(function: Callable[..., Any]) -> CodeIdentity:
    module_name = getattr(function, "__module__", "<unknown>")
    distribution_name, distribution_version = _distribution_for_module(module_name)
    source_path = inspect.getsourcefile(function)
    source_hash = function_source_hash(function) or _hash_path(source_path)
    suffix = Path(source_path).suffix.lower() if source_path else ""
    return CodeIdentity(
        distribution_name=distribution_name,
        distribution_version=distribution_version,
        module_name=module_name,
        qualified_name=getattr(function, "__qualname__", getattr(function, "__name__", None)),
        source_path=source_path,
        source_hash=source_hash,
        bytecode_hash=_code_hash(function),
        native_extension=suffix in {".so", ".pyd", ".dll", ".dylib"},
    )


def inventory_distribution(name: str) -> DependencyIdentity:
    distribution = importlib.metadata.distribution(name)
    file_names: list[str] = []
    file_hashes: dict[str, str] = {}
    native_extensions: list[str] = []
    for item in distribution.files or ():
        relative = str(item)
        file_names.append(relative)
        located = distribution.locate_file(item)
        digest = _hash_path(located)
        if digest is not None:
            file_hashes[relative] = digest
        if Path(relative).suffix.lower() in {".so", ".pyd", ".dll", ".dylib"}:
            native_extensions.append(relative)
    entry_points = tuple(
        sorted(f"{entry.group}:{entry.name}={entry.value}" for entry in distribution.entry_points)
    )
    return DependencyIdentity(
        distribution_name=distribution.metadata.get("Name", name),
        distribution_version=distribution.version,
        files=tuple(sorted(file_names)),
        file_hashes=file_hashes,
        dependencies=tuple(sorted(distribution.requires or ())),
        entry_points=entry_points,
        native_extensions=tuple(sorted(native_extensions)),
    )
