from typing import Any


_TOP_LEVEL_FIELDS = {"Version", "Statement"}
_STATEMENT_FIELDS = {
    "Sid",
    "Effect",
    "Action",
    "NotAction",
    "Resource",
    "NotResource",
    "Condition",
}
_PERMISSION_PAIRS = (("Action", "NotAction"), ("Resource", "NotResource"))
_SUPPORTED_VERSIONS = {"2008-10-17", "2012-10-17"}


def validate_policy_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["Policy root must be a JSON object."]

    for field in document:
        if field == "Id":
            errors.append("Unsupported top-level field 'Id' in an identity-based policy.")
        elif field not in _TOP_LEVEL_FIELDS:
            errors.append(f"Unsupported top-level field {field!r}.")

    if "Version" in document:
        version = document["Version"]
        if not isinstance(version, str) or version not in _SUPPORTED_VERSIONS:
            errors.append(
                "Version must be either '2008-10-17' or '2012-10-17'."
            )

    if "Statement" not in document:
        errors.append("Missing required top-level field 'Statement'.")
        return errors

    statement_value = document["Statement"]
    if isinstance(statement_value, dict):
        statements = [statement_value]
    elif isinstance(statement_value, list):
        if not statement_value:
            errors.append("Statement must not be an empty array.")
            return errors
        statements = statement_value
    else:
        errors.append("Statement must be an object or a non-empty array of objects.")
        return errors

    seen_sids: set[str] = set()
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            errors.append(f"Statement[{index}] must be an object.")
            continue
        errors.extend(_validate_statement(statement, index, seen_sids))

    return errors


def _validate_statement(
    statement: dict[str, Any], index: int, seen_sids: set[str]
) -> list[str]:
    errors: list[str] = []
    prefix = f"Statement[{index}]"

    for field in statement:
        if field in {"Principal", "NotPrincipal"}:
            errors.append(
                f"Unsupported field {prefix}.{field} in an identity-based policy."
            )
        elif field not in _STATEMENT_FIELDS:
            errors.append(f"Unsupported statement field {prefix}.{field}.")

    if "Sid" in statement:
        sid = statement["Sid"]
        if not isinstance(sid, str) or not sid or not sid.isascii() or not sid.isalnum():
            errors.append(
                f"{prefix}.Sid must contain only ASCII letters and digits."
            )
        if isinstance(sid, str):
            if sid in seen_sids:
                errors.append(f"{prefix}.Sid duplicates another statement Sid.")
            seen_sids.add(sid)

    if "Effect" not in statement:
        errors.append(f"Missing required field {prefix}.Effect.")
    elif not isinstance(statement["Effect"], str) or statement["Effect"] not in {
        "Allow",
        "Deny",
    }:
        errors.append(f"{prefix}.Effect must be exactly 'Allow' or 'Deny'.")

    for first, second in _PERMISSION_PAIRS:
        first_present = first in statement
        second_present = second in statement
        if first_present == second_present:
            if first_present:
                errors.append(
                    f"{prefix} must contain exactly one of {first} and {second}; "
                    "both are present."
                )
            else:
                errors.append(
                    f"{prefix} must contain exactly one of {first} and {second}; "
                    "neither is present."
                )

        for field in (first, second):
            if field in statement:
                error = _permission_value_error(statement[field], f"{prefix}.{field}")
                if error:
                    errors.append(error)

    if "Condition" in statement:
        errors.extend(_validate_condition(statement["Condition"], f"{prefix}.Condition"))

    return errors


def _permission_value_error(value: Any, field: str) -> str | None:
    if isinstance(value, str):
        if value:
            return None
        return f"{field} must be a non-empty string or a non-empty array of strings."

    if isinstance(value, list):
        if value and all(isinstance(item, str) and item for item in value):
            return None
        return f"{field} must be a non-empty array of non-empty strings."

    return f"{field} must be a non-empty string or a non-empty array of strings."


def _validate_condition(value: Any, field: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{field} must be an object."]
    if not value:
        return [f"{field} must contain at least one condition operator."]

    errors: list[str] = []
    for operator, condition_entries in value.items():
        operator_field = f"{field}.{operator}"
        if not isinstance(condition_entries, dict):
            errors.append(f"{operator_field} must be an object.")
            continue
        if not condition_entries:
            errors.append(
                f"{operator_field} must contain at least one condition key/value entry."
            )
            continue

        for key, condition_value in condition_entries.items():
            key_field = f"{operator_field}.{key}"
            if isinstance(condition_value, str):
                continue
            if isinstance(condition_value, list) and condition_value and all(
                isinstance(item, str) for item in condition_value
            ):
                continue
            errors.append(
                f"{key_field} must be a string or a non-empty array of strings."
            )

    return errors
