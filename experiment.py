"""Local tool-boundary experiment; NOT an MCP protocol implementation.

POSIX only. Model output is untrusted data. Principal IDs, root configuration,
approval issuance and the separate approval_token channel are trusted host input.
Never expose approve_store() to the model as a tool.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import threading


class Rejected(ValueError):
    """The untrusted call or its capability was rejected."""


class LocalRouter:
    MAX_BYTES = 8192
    TOOLS = {"read_note", "store_note"}

    def __init__(self, roots: dict[str, Path]):
        if not hasattr(os, "O_NOFOLLOW") or os.name != "posix":
            raise RuntimeError("This experiment requires POSIX O_NOFOLLOW/dir_fd")
        self._roots: dict[str, tuple[Path, int]] = {}
        self._approvals: dict[str, str] = {}
        self._lock = threading.Lock()
        for principal, configured in roots.items():
            # Configuration is host-owned, never selected by model arguments.
            root = Path(configured).resolve(strict=True)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._roots[principal] = (root, fd)

    def close(self):
        for _, fd in self._roots.values():
            os.close(fd)
        self._roots.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _validate(self, principal, call):
        if principal not in self._roots:
            raise Rejected("unknown principal")
        if type(call) is not dict or set(call) != {"tool", "args"}:
            raise Rejected("exact tool/args schema required")
        tool, args = call["tool"], call["args"]
        if type(tool) is not str or tool not in self.TOOLS:
            raise Rejected("tool not allowlisted")
        required = {"path", "content"} if tool == "store_note" else {"path"}
        if type(args) is not dict or set(args) != required:
            raise Rejected("exact argument schema required")
        # Snapshot strings before binding approval, not a caller-mutable dict.
        args = dict(args)
        name = args["path"]
        if type(name) is not str or not 1 <= len(name) <= 256:
            raise Rejected("invalid path type/length")
        parts = name.split("/")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", p)
               or p in {".", ".."} for p in parts):
            raise Rejected("only simple relative note paths are allowed")
        root, _ = self._roots[principal]
        try:
            target = root.joinpath(*parts).resolve(strict=False)
            target.relative_to(root)
        except (ValueError, OSError, RuntimeError) as exc:
            raise Rejected("path escapes principal root") from exc
        if tool == "store_note":
            if type(args["content"]) is not str:
                raise Rejected("content must be text")
            try:
                size = len(args["content"].encode("utf-8"))
            except UnicodeError as exc:
                raise Rejected("content must encode as UTF-8") from exc
            if size > self.MAX_BYTES:
                raise Rejected("content too large")
        canonical = {"principal": principal, "tool": tool,
                     "target": str(target), "args": args}
        fingerprint = hashlib.sha256(json.dumps(
            canonical, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        return tool, args, parts, fingerprint

    def approve_store(self, principal: str, args: dict) -> str:
        """Trusted approval interface, called only after exact args are reviewed.

        It returns an opaque one-shot capability. An argument such as
        approved=True in model output cannot call this interface or replace it.
        """
        _, _, parts, fingerprint = self._validate(
            principal, {"tool": "store_note", "args": args})
        # Detect even in-root symlinks before issuing a capability.
        parent = self._open_parent(principal, parts)
        try:
            if self._exists(parent, parts[-1]):
                raise Rejected("destination already exists")
        finally:
            os.close(parent)
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._approvals[token] = fingerprint
        return token

    def _open_parent(self, principal, parts):
        fd = os.dup(self._roots[principal][1])
        try:
            for component in parts[:-1]:
                nxt = os.open(component,
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except OSError as exc:
            os.close(fd)
            raise Rejected("missing directory or symlink component") from exc

    @staticmethod
    def _exists(parent, name):
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def execute(self, principal: str, call: dict, *, approval_token=None):
        """Host supplies principal and optional capability outside model data."""
        tool, args, parts, fingerprint = self._validate(principal, call)
        if tool == "read_note":
            parent = self._open_parent(principal, parts)
            try:
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise Rejected("not a regular note file")
                    content = b""
                    while len(content) <= self.MAX_BYTES:
                        piece = os.read(fd, self.MAX_BYTES + 1 - len(content))
                        if not piece:
                            break
                        content += piece
                    if len(content) > self.MAX_BYTES:
                        raise Rejected("note too large")
                    return {"status": "read", "content": content.decode("utf-8")}
                finally:
                    os.close(fd)
            except (OSError, UnicodeError) as exc:
                raise Rejected("note unavailable or invalid UTF-8") from exc
            finally:
                os.close(parent)

        if type(approval_token) is not str:
            raise Rejected("trusted approval capability required")
        with self._lock:
            if self._approvals.get(approval_token) != fingerprint:
                raise Rejected("approval does not match principal and exact args")
            # Consumed before writing: even an I/O failure requires new approval.
            del self._approvals[approval_token]
        parent = self._open_parent(principal, parts)
        tempname = ".pending-" + secrets.token_hex(16)
        created = False
        try:
            fd = os.open(tempname, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            created = True
            with os.fdopen(fd, "wb") as output:
                output.write(args["content"].encode("utf-8"))
                output.flush()
                os.fsync(output.fileno())
            # Atomic no-clobber publication on this local filesystem. A raced-in
            # destination (file/symlink) causes FileExistsError, never overwrite.
            os.link(tempname, parts[-1], src_dir_fd=parent,
                    dst_dir_fd=parent, follow_symlinks=False)
            return {"status": "stored", "path": args["path"]}
        except OSError as exc:
            raise Rejected("store failed; existing files are never overwritten") from exc
        finally:
            try:
                if created:
                    os.unlink(tempname, dir_fd=parent)
            finally:
                os.close(parent)


def main():
    """A synthetic local demonstration, without LLM/API/network access."""
    with tempfile.TemporaryDirectory(prefix="tool-boundary-demo-") as directory:
        base = Path(directory)
        (base / "alice").mkdir()
        (base / "bob").mkdir()
        (base / "outside.txt").write_text("synthetic secret", encoding="utf-8")
        with LocalRouter({"alice": base / "alice", "bob": base / "bob"}) as router:
            call = {"tool": "store_note", "args": {
                "path": "article.txt", "content": "A synthetic safe draft."}}
            result = {}
            probes = {
                "unapproved_store": lambda: router.execute("alice", call),
                "model_approved_flag": lambda: router.execute("alice", {
                    "tool": "store_note", "args": {**call["args"], "approved": True}}),
                "traversal_read": lambda: router.execute("alice", {
                    "tool": "read_note", "args": {"path": "../outside.txt"}}),
            }
            for name, operation in probes.items():
                try:
                    operation()
                    result[name] = "unexpectedly_allowed"
                except Rejected:
                    result[name] = "rejected"
            # This trusted call is performed by the demo host, not by the model.
            token = router.approve_store("alice", call["args"])
            result["approved_store"] = router.execute("alice", call, approval_token=token)
            try:
                router.execute("alice", call, approval_token=token)
                result["approval_reuse"] = "unexpectedly_allowed"
            except Rejected:
                result["approval_reuse"] = "rejected"
            result["read_back"] = router.execute("alice", {
                "tool": "read_note", "args": {"path": "article.txt"}})
            print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
