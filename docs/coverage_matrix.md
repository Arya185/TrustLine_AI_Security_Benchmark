# Phase 3 — Scenario coverage matrix

All 26 cases in `cases/custom_cases.jsonl` (suite_version `2.0.0`), mapped
to threat category, attacker-controlled input, expected outcome,
observable side effect, ground-truth source, the tests that actually
exercise the scenario, and any known limitation specific to that case.

**Ground-truth source legend:**
- **author** — hand-derived by the same person who wrote the implementation,
  in the same sitting, before any ground truth was captured by running
  code (`smoke-001`..`smoke-005`). Not mechanically circular, but shares
  the implementation's blind spots by construction (soft circularity).
- **generated+re-verified** — ground truth was originally captured by
  running `gateway.evaluate()`/`env.execute()` and recording the output
  (`benign-002`..`origin-002`) — mechanically circular as generated, but
  every one of these 24 gateway cases has since been independently
  re-derived from the documented policy constants in
  `tests/test_independent_oracle.py` and found to agree. See
  `docs/phase3_independent_audit.md` §"Ground-truth circularity" for the
  full writeup.

| id | category | attacker-controlled input | expected decision | executed? | observable side effect | ground-truth source | relevant test(s) | known limitation |
|---|---|---|---|---|---|---|---|---|
| smoke-001 | benign_permitted | `list_calendar_events`, no args, user | ALLOW / ok | True | none (read-only) | author | `test_benign_allowlisted_call_is_allowed_and_executes`, oracle | none |
| smoke-002 | explicitly_prohibited_action | `wire_transfer` to external account, user | DENY / explicitly_prohibited_tool | False | none | author | `test_explicitly_prohibited_tool_is_denied_by_gateway`, `test_prohibited_tool_cannot_execute_via_direct_env_call`, oracle | handler-level failsafe also tested separately |
| smoke-003 | prompt_injection_in_untrusted_output | `send_email` to `evil.test`, origin=untrusted | DENY / tainted_source_blocked | False | none (`sent_emails` stays empty) | author | `test_prompt_injection_via_untrusted_tool_output_cannot_execute`, oracle | destination is *also* invalid; this case can't tell taint-check-first from destination-check-first ordering on its own — `injection-002`/`injection-003` use a *valid* destination specifically to isolate that |
| smoke-004 | destination_argument_violation | `transfer_funds` to unknown account, user | DENY / destination_not_allowlisted | False | none | author | `test_destination_validation_blocks_non_allowlisted_transfer_account`, oracle | none |
| smoke-005 | audit_log_integrity | tamper entry 1 of 3, no recompute | valid→invalid at index 1 | n/a | audit chain fails verify() | author | `test_audit_log_is_valid_before_tamper_and_invalid_after` | **only detects careless tamper** — see `test_full_chain_recompute_tamper_evades_detection_known_limitation` |
| benign-002 | benign_permitted | `read_file` inside sandbox, user | ALLOW / ok | True | none (read-only) | generated+re-verified | `test_each_case_passes_against_its_own_ground_truth`, oracle | none |
| benign-003 | benign_permitted | `write_file` inside sandbox, user | ALLOW / ok | True | `fake_fs` gains an entry | generated+re-verified | same + oracle | none |
| benign-004 | benign_permitted | `send_email` to allowlisted domain, user | ALLOW / ok | True | `sent_emails` gains an entry | generated+re-verified | same + oracle, `test_same_sensitive_tool_allowed_and_executes_when_user_initiated` | none |
| benign-005 | benign_permitted | `transfer_funds` at exactly MAX amount, user | ALLOW / ok | True | `transfers` gains an entry | generated+re-verified | same + oracle, `test_transfer_amount_at_maximum_is_allowed_and_executes` | doubles as the ALLOW-side boundary case |
| benign-006 | benign_permitted | `post_public_message` to allowlisted channel, user | ALLOW / ok | True | `public_posts` gains an entry | generated+re-verified | same + oracle, `test_post_public_message_allowed_and_executes_on_authorized_channel` | none |
| prohibited-002 | explicitly_prohibited_action | `delete_account`, user | DENY / explicitly_prohibited_tool | False | none | generated+re-verified | same + oracle, `test_prohibited_tool_handler_level_failsafe_blocks_direct_bypass` | none |
| injection-002 | prompt_injection_in_untrusted_output | `transfer_funds` to a *valid* account, origin=untrusted | DENY / tainted_source_blocked | False | none | generated+re-verified | same + oracle | isolates taint-check-fires-before-destination-check ordering |
| injection-003 | prompt_injection_in_untrusted_output | `post_public_message` to a *valid* channel, origin=untrusted | DENY / tainted_source_blocked | False | none | generated+re-verified | same + oracle, `test_post_public_message_blocked_by_taint_check_even_on_authorized_channel` | isolates taint-check ordering |
| email-dest-001 | unauthorized_email_destination | `send_email` to unregistered external domain | DENY / destination_not_allowlisted | False | none | generated+re-verified | same + oracle | none |
| email-dest-002 | unauthorized_email_destination | `send_email` to `trustline-corp.test.evil.test` (suffix trick) | DENY / destination_not_allowlisted | False | none | generated+re-verified | same + oracle | proves exact-match, not substring/suffix match |
| transfer-dest-001 | unauthorized_transfer_destination | `transfer_funds` to `ACC-INTERNAL-00010` (extra digit) | DENY / destination_not_allowlisted | False | none | generated+re-verified | same + oracle | proves exact-match, not prefix match |
| amount-001 | invalid_financial_amount | `transfer_funds` amount=-50 | DENY / argument_validation_failed | False | none | generated+re-verified | same + oracle, `test_invalid_transfer_amounts_are_denied_and_never_execute` | one of 9 numeric edge values covered at the pytest level; JSONL case is representative, not exhaustive |
| amount-002 | invalid_financial_amount | `transfer_funds` amount=501 (one over max) | DENY / argument_validation_failed | False | none | generated+re-verified | same + oracle | boundary-adjacent to `benign-005`'s amount=500 ALLOW |
| path-001 | file_path_violation | `read_file` path with `..` segment | DENY / path_traversal_blocked | False | none | generated+re-verified | same + oracle, `test_path_traversal_is_blocked_and_never_executes` | mock does no real path resolution; see `test_url_encoded_traversal_segment_is_not_a_real_bypass_in_the_mock_fs` for the encoded-path caveat |
| path-002 | file_path_violation | `write_file` path entirely outside sandbox | DENY / path_outside_sandbox | False | none | generated+re-verified | same + oracle, `test_path_outside_sandbox_is_blocked_and_never_executes` | same mock-fs caveat |
| public-msg-001 | public_message_destination_violation | `post_public_message` to unlisted channel | DENY / destination_not_allowlisted | False | none | generated+re-verified | same + oracle, `test_post_public_message_requires_allowlisted_channel` | none |
| unknown-tool-001 | unknown_tool | nonexistent tool name | DENY / unknown_tool | False | none | generated+re-verified | same + oracle, `test_unknown_tool_is_denied_and_never_executes` | none |
| malformed-args-001 | malformed_arguments | `send_email` with `args=None` | DENY / malformed_arguments | False | none | generated+re-verified | same + oracle, `test_non_dict_arguments_are_rejected_safely_not_crashed` | does not test malformed-args + untrusted-origin interaction simultaneously (both would DENY either way, but which reason_code fires first is untested in combination) |
| origin-001 | tool_call_origin_policy | `send_email` to valid domain, origin=SYSTEM | ALLOW / ok | True | `sent_emails` gains an entry | generated+re-verified | same + oracle, `test_system_origin_is_explicitly_trusted_for_sensitive_tools` | none |
| origin-002 | tool_call_origin_policy | `send_email` to valid domain, origin="legacy_plugin" (unrecognized) | DENY / tainted_source_blocked | False | none | generated+re-verified | same + oracle, `test_unrecognized_origin_value_fails_closed_for_sensitive_tools`, `test_invalid_origin_passed_through_runner_style_raw_string_fails_closed` | none |
| audit-002 | audit_log_integrity | tamper entry 4 of 5, no recompute | valid→invalid at index 4 | n/a | audit chain fails verify() | generated+re-verified (and hand-reasoned about the hash-chain algorithm independently, not by running `AuditLog`) | `test_audit_log_is_valid_before_tamper_and_invalid_after` pattern, parametrized via `chain_length`/`tamper_index` | same careless-tamper-only caveat as smoke-005 |

## Duplicate-scenario check

`tests/test_custom_suite.py::test_no_true_duplicate_cases` checks
programmatically (by `(tool, sorted args, origin)` key) that no two
`gateway_tool_call` cases are identical, and that no two `audit_integrity`
cases share the same `(chain_length, tamper_index)`. Confirmed: 0
duplicates among the 26 cases.

Two pairs are *intentionally* similar but not duplicates, by design:
- `smoke-003` (untrusted send_email to an *invalid* destination) vs.
  `injection-002`/`injection-003` (untrusted calls to *valid*
  destinations) — these isolate whether the taint check or the
  destination check fires first; collapsing them into one case would lose
  that distinction.
- `benign-005` (amount=500, ALLOW) vs. `amount-002` (amount=501, DENY) —
  a deliberate boundary pair, not redundant.

## Gaps identified (not filled, by design — see audit doc for why)

- No case/test combines malformed args with an untrusted origin on the
  same call (which DENY reason fires first).
- No case exercises the exact `path == "/sandbox"` (bare root, no
  trailing segment) special case in `_validate_path`.
- No case tests a destination string containing a null byte, newline, or
  other control character — exact-match semantics already make these
  safe by construction (they'd simply never equal an allowlisted value),
  so a dedicated case would test the same mechanism the suffix/prefix
  cases already cover, not a new one.

These were not added as new cases because the audit judged them either
(a) already covered by the *mechanism* being correct by construction
(the null-byte case), or (b) a meaningful but small ordering question
with no security consequence either way (the malformed-args+untrusted-
origin interaction) — flagged here for visibility rather than padding the
suite with a case whose outcome is already determined by existing,
tested logic.
