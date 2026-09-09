"""Small descriptor-relative helpers for filesystem-bound Caretaker writers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO
from uuid import uuid4


class RootedWriteError(ValueError):
    """Raised when a configured output path cannot be safely confined."""


class RootedFilesystem:
    """Open and replace files relative to one trusted, non-symlinked root."""

    def __init__(self, root: str | Path) -> None:
        candidate = Path(root).expanduser()
        if not candidate.is_absolute():
            candidate = Path(os.path.abspath(candidate))
        self.root = candidate
        try:
            root_stat = os.lstat(self.root)
        except OSError as exc:
            raise RootedWriteError(f"root directory is unavailable: {self.root}") from exc
        if not os.path.isdir(self.root) or os.path.islink(self.root):
            raise RootedWriteError(f"root directory must be a real directory: {self.root}")
        if root_stat.st_mode & 0o002:
            raise RootedWriteError(f"root directory must not be world-writable: {self.root}")

    def path(self, value: str | Path) -> Path:
        """Return a path only after lexical containment has been established."""
        supplied = Path(value)
        if supplied.is_absolute():
            target = supplied
            try:
                relative = target.relative_to(self.root)
            except ValueError as exc:
                raise RootedWriteError(f"path escapes configured root: {target}") from exc
        else:
            relative = supplied
            target = self.root / relative
        if any(part in {"..", ""} for part in relative.parts):
            raise RootedWriteError(f"path contains an unsafe component: {value}")
        normalized = Path(os.path.abspath(target))
        try:
            normalized.relative_to(self.root)
        except ValueError as exc:
            raise RootedWriteError(f"path escapes configured root: {target}") from exc
        return normalized

    @staticmethod
    def _directory_flags() -> int:
        return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)

    def _open_parent(self, target: Path) -> tuple[int, str]:
        target = self.path(target)
        relative = target.relative_to(self.root)
        if not relative.name:
            raise RootedWriteError("a file path is required")
        directory_fd = os.open(self.root, self._directory_flags())
        try:
            for component in relative.parts[:-1]:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, self._directory_flags(), dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            return directory_fd, relative.name
        except Exception:
            os.close(directory_fd)
            raise

    def open_append(self, target: str | Path, *, text: bool = False):
        directory_fd, name = self._open_parent(self.path(target))
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        if text:
            return os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)
        return os.fdopen(descriptor, "ab", buffering=0)

    def open_exclusive(self, target: str | Path, *, text: bool = False):
        directory_fd, name = self._open_parent(self.path(target))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        if text:
            return os.fdopen(descriptor, "w", encoding="utf-8")
        return os.fdopen(descriptor, "wb", buffering=0)

    def read_bytes(self, target: str | Path) -> bytes:
        directory_fd, name = self._open_parent(self.path(target))
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        try:
            with os.fdopen(descriptor, "rb") as stream:
                return stream.read()
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def atomic_write(self, target: str | Path, payload: bytes, *, mode: int = 0o600) -> Path:
        """Write bytes through an in-root temporary and atomically replace target."""
        target = self.path(target)
        directory_fd, name = self._open_parent(target)
        temporary_name = f".{name}.{uuid4().hex}.tmp"
        descriptor = None
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                mode,
                dir_fd=directory_fd,
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None and os.path.islink(target):
                raise RootedWriteError(f"destination is a symlink: {target}")
            os.replace(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
            return target
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory_fd)

    def replace(self, source: str | Path, target: str | Path) -> Path:
        """Atomically rename one existing in-root file to another in-root name."""
        source = self.path(source)
        target = self.path(target)
        source_relative = source.relative_to(self.root)
        target_relative = target.relative_to(self.root)
        if source_relative.parent != target_relative.parent:
            raise RootedWriteError("rooted replacement requires one parent directory")
        directory_fd, target_name = self._open_parent(target)
        source_name = source_relative.name
        try:
            os.stat(source_name, dir_fd=directory_fd, follow_symlinks=False)
            if os.path.islink(source) or os.path.islink(target):
                raise RootedWriteError("rooted replacement cannot use a symlink")
            os.replace(
                source_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            try:
                os.fsync(directory_fd)
            except OSError:
                pass
        finally:
            os.close(directory_fd)
        return target


__all__ = ["RootedFilesystem", "RootedWriteError"]
