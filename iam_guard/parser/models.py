from dataclasses import dataclass
from typing import Any


@dataclass
class PolicyStatement:
    statement_index: int
    sid: str | None
    effect: str
    actions: list[str] | None
    not_actions: list[str] | None
    resources: list[str] | None
    not_resources: list[str] | None
    conditions: dict[str, Any] | None


@dataclass
class ParsedPolicy:
    provider: str
    policy_type: str
    original_json: str
    original_document: dict[str, Any]
    version: str | None
    statements: list[PolicyStatement]


@dataclass
class ParseResult:
    success: bool
    policy: ParsedPolicy | None
    errors: list[str]
