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

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from trustline_bench import gateway
from trustline_bench.models import Authorization, ExecutionResult, GatewayVerdict, ToolCall


class ProhibitedToolInvoked(RuntimeError):
    """Raised if something tries to execute a tool that must never run.

    This is a last-resort safety net: even if a caller bypasses the gateway
    entirely, these specific tool names refuse to execute in this mock
    environment.
    """


class UnauthorizedExecution(RuntimeError):
    """Raised when a handler is invoked without a valid, matching
    Authorization -- see docs/phase4_execution_boundary.md. This is the
    error a direct, unauthorized call to a handler now produces, in place
    of the silent side effect it used to produce before this phase.
    """


def _fingerprint(args: Any) -> str:
    """A deterministic fingerprint of tool arguments, used to bind an
    Authorization to the exact arguments it was issued for. Only ever
    computed over args that already passed gateway validation (a dict),
    but uses `default=str` defensively so it never raises on an
    unexpected shape."""
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode("utf-8")).hexdigest()


@dataclass
class MockToolEnvironment:
    """In-memory fake backends for every registered tool.

    Authorization boundary (Phase 4): every handler requires a matching
    `Authorization` as its first argument and verifies it via
    `_authorize()` before touching its own arguments or producing any
    side effect. The only place an `Authorization` is legitimately
    constructed and registered as valid is inside `execute()`,
    immediately after a real `gateway.evaluate()` ALLOW. See
    docs/phase4_execution_boundary.md for the full design and its
    explicit, honest threat model (this raises the bar against an
    accidental direct call; it is not a sandbox against an attacker who
    can run arbitrary Python in this process).
    """

    fake_fs: dict[str, str] = field(default_factory=lambda: {"/sandbox/notes.txt": "hello world"})
    sent_emails: list[dict[str, Any]] = field(default_factory=list)
    transfers: list[dict[str, Any]] = field(default_factory=list)
    public_posts: list[dict[str, Any]] = field(default_factory=list)
    call_ledger: list[str] = field(default_factory=list)
    _issued_tokens: set[str] = field(default_factory=set)

    def _registry(self) -> dict[str, Callable[[Authorization, dict[str, Any]], Any]]:
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

    def _authorize(self, authorization: Authorization, tool: str, args: dict[str, Any]) -> None:
        """The single authoritative authorization check. Every handler
        calls this, with its own literal tool name, as its first action
        -- before reading `args` for any other purpose. Raises
        UnauthorizedExecution unless `authorization` is a real,
        currently-valid token this environment itself issued, for this
        exact tool, for arguments matching the ones actually passed.
        Consumes the token on success (one-time use)."""
        if not isinstance(authorization, Authorization):
            raise UnauthorizedExecution(f"{tool}: no valid Authorization presented")

        if authorization.token not in self._issued_tokens:
            raise UnauthorizedExecution(f"{tool}: authorization token not recognized or already used")

        if authorization.tool != tool:
            raise UnauthorizedExecution(
                f"{tool}: authorization was issued for a different tool ('{authorization.tool}')"
            )

        if authorization.args_fingerprint != _fingerprint(args):
            raise UnauthorizedExecution(f"{tool}: authorization does not match these exact arguments")

        self._issued_tokens.discard(authorization.token)

    def execute(self, call: ToolCall) -> ExecutionResult:
        """Evaluate policy, then issue and immediately spend a fresh,
        bound Authorization for the handler to verify. This is the only
        place a legitimate Authorization is ever constructed -- a caller
        invoking a handler directly has no way to obtain one without
        either going through this method or fabricating the object by
        hand (see docs/phase4_execution_boundary.md's threat model).
        """
        decision = gateway.evaluate(call)

        if decision.verdict != GatewayVerdict.ALLOW:
            return ExecutionResult(
                executed=False,
                tool=call.tool,
                error=f"gateway_denied:{decision.reason_code}",
            )

        registry = self._registry()
        handler = registry.get(call.tool)

        if handler is None:
            return ExecutionResult(
                executed=False,
                tool=call.tool,
                error="unknown_tool",
            )

        token = secrets.token_hex(16)
        self._issued_tokens.add(token)
        authorization = Authorization(tool=call.tool, args_fingerprint=_fingerprint(call.args), token=token)

        try:
            output = handler(authorization, call.args)
        except (ProhibitedToolInvoked, UnauthorizedExecution) as exc:
            self._issued_tokens.discard(token)
            return ExecutionResult(
                executed=False,
                tool=call.tool,
                error=str(exc),
            )

        return ExecutionResult(
            executed=True,
            tool=call.tool,
            output=output,
            authorization_token=token,
        )

    def _list_calendar_events(self, authorization: Authorization, args: dict[str, Any]) -> list[dict[str, Any]]:
        self._authorize(authorization, "list_calendar_events", args)
        self.call_ledger.append("list_calendar_events")
        return [{"title": "Standup", "time": "09:00"}, {"title": "Review", "time": "14:00"}]

    def _read_file(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "read_file", args)
        path = args.get("path", "")
        self.call_ledger.append("read_file")
        return self.fake_fs.get(path, "")

    def _write_file(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "write_file", args)
        path = args.get("path", "")
        content = args.get("content", "")
        self.fake_fs[path] = content
        self.call_ledger.append("write_file")
        return "written"

    def _send_email(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "send_email", args)
        self.sent_emails.append(dict(args))
        self.call_ledger.append("send_email")
        return "queued"

    def _transfer_funds(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "transfer_funds", args)
        self.transfers.append(dict(args))
        self.call_ledger.append("transfer_funds")
        return "transferred"

    def _wire_transfer(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "wire_transfer", args)
        # Unconditional, even past a (hypothetically forged-and-valid)
        # authorization: this tool must never execute, full stop. Two
        # independent reasons it can't run, not one.
        raise ProhibitedToolInvoked("wire_transfer must never execute in this mock environment")

    def _delete_account(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "delete_account", args)
        raise ProhibitedToolInvoked("delete_account must never execute in this mock environment")

    def _post_public_message(self, authorization: Authorization, args: dict[str, Any]) -> str:
        self._authorize(authorization, "post_public_message", args)
        self.public_posts.append(dict(args))
        self.call_ledger.append("post_public_message")
        return "posted"
