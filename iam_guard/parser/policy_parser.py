import json
from copy import deepcopy
from typing import Any

from .models import ParseResult, ParsedPolicy, PolicyStatement
from .validator import validate_policy_document


class _DuplicateJSONKeyError(ValueError):
    pass


class _InvalidJSONConstantError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(f"Duplicate JSON object key {key!r}.")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise _InvalidJSONConstantError(
        f"Non-standard JSON constant {value!r} is not permitted."
    )


def parse_policy(raw_json: str) -> ParseResult:
    """Parse and structurally validate an AWS identity-based IAM policy."""
    if not isinstance(raw_json, str):
        return ParseResult(
            success=False,
            policy=None,
            errors=["Policy input must be a JSON string."],
        )

    try:
        document = json.loads(
            raw_json,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJSONKeyError as error:
        return ParseResult(success=False, policy=None, errors=[str(error)])
    except _InvalidJSONConstantError as error:
        return ParseResult(success=False, policy=None, errors=[str(error)])
    except json.JSONDecodeError as error:
        return ParseResult(
            success=False,
            policy=None,
            errors=[
                f"Invalid JSON at line {error.lineno}, column {error.colno}: "
                f"{error.msg}."
            ],
        )

    errors = validate_policy_document(document)
    if errors:
        return ParseResult(success=False, policy=None, errors=errors)

    raw_statements = document["Statement"]
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]

    statements = [
        _build_statement(statement, index)
        for index, statement in enumerate(raw_statements)
    ]
    policy = ParsedPolicy(
        provider="aws",
        policy_type="identity_based",
        original_json=raw_json,
        original_document=document,
        version=document.get("Version"),
        statements=statements,
    )
    return ParseResult(success=True, policy=policy, errors=[])


def _build_statement(statement: dict[str, Any], index: int) -> PolicyStatement:
    return PolicyStatement(
        statement_index=index,
        sid=statement.get("Sid"),
        effect=statement["Effect"],
        actions=_normalize_permission(statement, "Action"),
        not_actions=_normalize_permission(statement, "NotAction"),
        resources=_normalize_permission(statement, "Resource"),
        not_resources=_normalize_permission(statement, "NotResource"),
        conditions=deepcopy(statement.get("Condition")),
    )


def _normalize_permission(
    statement: dict[str, Any], field: str
) -> list[str] | None:
    if field not in statement:
        return None
    value = statement[field]
    return [value] if isinstance(value, str) else list(value)
