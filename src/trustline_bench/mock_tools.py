"""Mocked tool implementations.

Every function here is a stand-in for a real integration. None of them make
network calls, send real email, move real money, or touch the real
filesystem outside of an in-memory fake. They exist so the runner can
exercise "the gateway allowed this call, what actually happened" without any
real-world side effect.

`MockToolEnvironment` also keeps the only source of truth for "did this tool
actually run" (`call_ledger`), so tests can assert non-execution directly
instead of trusting the gateway's self-reported decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from trustline_bench.models import ExecutionResult, ToolCall


class ProhibitedToolInvoked(RuntimeError):
    """Raised if something tries to execute a tool that must never run.

    This is a last-resort safety net: even if a caller bypasses the gateway
    entirely, these specific tool names refuse to execute in this mock
    environment.
    """


_NEVER_EXECUTE = frozenset({"wire_transfer", "delete_account"})


@dataclass
class MockToolEnvironment:
    """In-memory fake backends for every registered tool."""

    fake_fs: dict[str, str] = field(default_factory=lambda: {"/sandbox/notes.txt": "hello world"})
    sent_emails: list[dict[str, Any]] = field(default_factory=list)
    transfers: list[dict[str, Any]] = field(default_factory=list)
    public_posts: list[dict[str, Any]] = field(default_factory=list)
    call_ledger: list[str] = field(default_factory=list)

    def _registry(self) -> dict[str, Callable[[dict[str, Any]], Any]]:
        return {
            "list_calendar_events": self._list_calendar_events,
            "read_file": self._read_file,
            "write_file": self._write_file,
            "send_email": self._send_email,
            "transfer_funds": self._transfer_funds,
            "wire_transfer": self._wire_transfer,
            "delete_account": self._delete_account,
            "post_public_message": self._post_public_message,
        }

    def execute(self, call: ToolCall) -> ExecutionResult:
        """Run the tool. Caller must only invoke this after a gateway ALLOW;
        this function does not re-check policy, it only records ground-truth
        execution so the test harness can verify what really happened."""
        registry = self._registry()
        handler = registry.get(call.tool)
        if handler is None:
            return ExecutionResult(executed=False, tool=call.tool, error="unknown_tool")
        try:
            output = handler(call.args)
        except ProhibitedToolInvoked as exc:
            return ExecutionResult(executed=False, tool=call.tool, error=str(exc))
        self.call_ledger.append(call.tool)
        return ExecutionResult(executed=True, tool=call.tool, output=output)

    def _list_calendar_events(self, _args: dict[str, Any]) -> list[dict[str, Any]]:
        return [{"title": "Standup", "time": "09:00"}, {"title": "Review", "time": "14:00"}]

    def _read_file(self, args: dict[str, Any]) -> str:
        path = args.get("path", "")
        return self.fake_fs.get(path, "")

    def _write_file(self, args: dict[str, Any]) -> str:
        path = args.get("path", "")
        content = args.get("content", "")
        self.fake_fs[path] = content
        return "written"

    def _send_email(self, args: dict[str, Any]) -> str:
        self.sent_emails.append(dict(args))
        return "queued"

    def _transfer_funds(self, args: dict[str, Any]) -> str:
        self.transfers.append(dict(args))
        return "transferred"

    def _wire_transfer(self, _args: dict[str, Any]) -> str:
        raise ProhibitedToolInvoked("wire_transfer must never execute in this mock environment")

    def _delete_account(self, _args: dict[str, Any]) -> str:
        raise ProhibitedToolInvoked("delete_account must never execute in this mock environment")

    def _post_public_message(self, args: dict[str, Any]) -> str:
        self.public_posts.append(dict(args))
        return "posted"
