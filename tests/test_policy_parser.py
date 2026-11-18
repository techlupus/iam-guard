import json
import unittest

from iam_guard.parser.models import ParseResult, ParsedPolicy, PolicyStatement
from iam_guard.parser.policy_parser import parse_policy


def make_policy(statement=None, **fields):
    policy = {"Statement": statement if statement is not None else {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/*",
    }}
    policy.update(fields)
    return json.dumps(policy)


class ParsePolicyTests(unittest.TestCase):
    def assert_rejected(self, raw_json, expected_error=None):
        result = parse_policy(raw_json)
        self.assertIsInstance(result, ParseResult)
        self.assertFalse(result.success)
        self.assertIsNone(result.policy)
        self.assertTrue(result.errors)
        if expected_error is not None:
            self.assertTrue(
                any(expected_error in error for error in result.errors),
                result.errors,
            )
        return result

    def test_valid_identity_policy_and_single_statement_object(self):
        raw_json = make_policy()
        result = parse_policy(raw_json)

        self.assertTrue(result.success)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.policy.provider, "aws")
        self.assertEqual(result.policy.policy_type, "identity_based")
        self.assertEqual(result.policy.original_json, raw_json)
        self.assertEqual(len(result.policy.statements), 1)
        self.assertEqual(result.policy.statements[0].statement_index, 0)
        self.assertIsInstance(result.policy, ParsedPolicy)
        self.assertIsInstance(result.policy.statements[0], PolicyStatement)

    def test_multiple_statements_preserve_order_and_indexes(self):
        statements = [
            {"Sid": "First", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "Second", "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ]
        result = parse_policy(make_policy(statements))

        self.assertTrue(result.success, result.errors)
        self.assertEqual([item.sid for item in result.policy.statements], ["First", "Second"])
        self.assertEqual(
            [item.statement_index for item in result.policy.statements], [0, 1]
        )

    def test_statement_is_required_and_cannot_be_empty(self):
        self.assert_rejected("{}", "Statement")
        self.assert_rejected('{"Statement": []}', "empty array")

    def test_scalar_and_array_permissions_are_normalized(self):
        result = parse_policy(
            make_policy(
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": ["arn:example:one", "arn:example:two"],
                }
            )
        )

        self.assertTrue(result.success, result.errors)
        statement = result.policy.statements[0]
        self.assertEqual(statement.actions, ["s3:GetObject", "s3:PutObject"])
        self.assertEqual(statement.resources, ["arn:example:one", "arn:example:two"])

    def test_scalar_permissions_become_single_item_lists(self):
        result = parse_policy(make_policy())

        self.assertTrue(result.success, result.errors)
        statement = result.policy.statements[0]
        self.assertEqual(statement.actions, ["s3:GetObject"])
        self.assertEqual(statement.resources, ["arn:aws:s3:::example/*"])

    def test_wildcards_are_preserved(self):
        result = parse_policy(make_policy({
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }))

        self.assertTrue(result.success, result.errors)
        self.assertEqual(result.policy.statements[0].actions, ["*"])
        self.assertEqual(result.policy.statements[0].resources, ["*"])

    def test_not_action_and_not_resource_are_not_combined(self):
        result = parse_policy(make_policy({
            "Effect": "Deny",
            "NotAction": ["s3:GetObject", "s3:ListBucket"],
            "NotResource": "arn:aws:s3:::private/*",
        }))

        self.assertTrue(result.success, result.errors)
        statement = result.policy.statements[0]
        self.assertIsNone(statement.actions)
        self.assertEqual(statement.not_actions, ["s3:GetObject", "s3:ListBucket"])
        self.assertIsNone(statement.resources)
        self.assertEqual(statement.not_resources, ["arn:aws:s3:::private/*"])

    def test_normalization_does_not_modify_original_document(self):
        raw_json = (
            '{"Statement":{"Effect":"Allow","Action":"s3:GetObject",'
            '"Resource":"*","Condition":{"StringEquals":{"aws:username":"alice"}}}}'
        )
        result = parse_policy(raw_json)

        self.assertTrue(result.success, result.errors)
        original_statement = result.policy.original_document["Statement"]
        parsed_statement = result.policy.statements[0]
        self.assertEqual(original_statement["Action"], "s3:GetObject")
        self.assertEqual(original_statement["Resource"], "*")
        self.assertEqual(parsed_statement.actions, ["s3:GetObject"])
        self.assertIsNot(original_statement["Condition"], parsed_statement.conditions)

    def test_supported_versions_and_missing_version(self):
        for version in ("2012-10-17", "2008-10-17"):
            with self.subTest(version=version):
                result = parse_policy(make_policy(Version=version))
                self.assertTrue(result.success, result.errors)
                self.assertEqual(result.policy.version, version)

        result = parse_policy(make_policy())
        self.assertTrue(result.success, result.errors)
        self.assertIsNone(result.policy.version)

    def test_unsupported_version_is_rejected(self):
        self.assert_rejected(make_policy(Version="2020-01-01"), "Version")
        self.assert_rejected(make_policy(Version=2012), "Version")

    def test_sid_validation_and_uniqueness(self):
        valid = parse_policy(make_policy({
            "Sid": "ReadOnly123",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
        }))
        self.assertTrue(valid.success, valid.errors)
        self.assertEqual(valid.policy.statements[0].sid, "ReadOnly123")

        for sid in ("bad-sid", "café", "", 12):
            with self.subTest(sid=sid):
                self.assert_rejected(make_policy({
                    "Sid": sid,
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }), "Sid")

        duplicate_sid = make_policy([
            {"Sid": "Same", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "Same", "Effect": "Deny", "Action": "*", "Resource": "*"},
        ])
        self.assert_rejected(duplicate_sid, "Statement[1].Sid")

    def test_condition_is_preserved(self):
        condition = {
            "StringEquals": {"aws:username": "alice"},
            "ForAnyValue:StringLike": {"aws:TagKeys": ["team", "project"]},
        }
        result = parse_policy(make_policy({
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": condition,
        }))

        self.assertTrue(result.success, result.errors)
        self.assertEqual(result.policy.statements[0].conditions, condition)

    def test_empty_condition_and_empty_operator_map_are_rejected(self):
        for condition, expected_error in (
            ({}, "at least one condition operator"),
            ({"StringEquals": {}}, "at least one condition key/value entry"),
        ):
            with self.subTest(condition=condition):
                result = self.assert_rejected(make_policy({
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": condition,
                }), "Condition")
                self.assertTrue(
                    any(expected_error in error for error in result.errors),
                    result.errors,
                )

    def test_invalid_condition_structures_are_rejected(self):
        invalid_conditions = (
            "not-an-object",
            {"StringEquals": "not-an-object"},
            {"StringEquals": {"key": []}},
            {"StringEquals": {"key": ["valid", 1]}},
            {"StringEquals": {"key": None}},
        )
        for condition in invalid_conditions:
            with self.subTest(condition=condition):
                self.assert_rejected(make_policy({
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": condition,
                }), "Condition")

    def test_effect_and_permission_pairs_are_required_and_exclusive(self):
        base = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        invalid_statements = (
            ({"Action": "*", "Resource": "*"}, "Effect"),
            ({**base, "Effect": "allow"}, "Effect"),
            ({"Effect": "Allow", "Resource": "*"}, "Action"),
            ({**base, "NotAction": "s3:PutObject"}, "Action and NotAction"),
            ({"Effect": "Allow", "Action": "*"}, "Resource"),
            ({**base, "NotResource": "*"}, "Resource and NotResource"),
        )
        for statement, expected_error in invalid_statements:
            with self.subTest(statement=statement):
                self.assert_rejected(make_policy(statement), expected_error)

    def test_invalid_json_and_non_standard_constants_are_rejected(self):
        self.assert_rejected('{"Statement":', "Invalid JSON")
        self.assert_rejected(
            '{"Statement":{"Effect":"Allow","Action":NaN,"Resource":"*"}}',
            "NaN",
        )
        self.assert_rejected(
            '{"Statement":{"Effect":"Allow","Action":"*","Resource":Infinity}}',
            "Infinity",
        )

    def test_duplicate_keys_are_rejected_at_every_nesting_level(self):
        self.assert_rejected(
            '{"Statement":{},"Statement":{}}',
            "Duplicate JSON object key",
        )
        self.assert_rejected(
            '{"Statement":{"Effect":"Allow","Action":"*","Resource":"*",'
            '"Condition":{"StringEquals":{"key":"one","key":"two"}}}}',
            "Duplicate JSON object key",
        )

    def test_invalid_root_and_statement_types_are_rejected(self):
        for raw_json in ("[]", "null", '"string"', "true", "1"):
            with self.subTest(raw_json=raw_json):
                self.assert_rejected(raw_json, "root")

        self.assert_rejected('{"Statement":42}', "Statement")
        self.assert_rejected('{"Statement":[{},"not-an-object"]}', "Statement[1]")

    def test_invalid_permission_types_and_empty_values_are_rejected(self):
        for field in ("Action", "NotAction", "Resource", "NotResource"):
            with self.subTest(field=field):
                other = "NotAction" if field == "Action" else "Action"
                resource = "NotResource" if field == "Resource" else "Resource"
                statement = {"Effect": "Allow", other: "*", resource: "*", field: 3}
                self.assert_rejected(make_policy(statement), f".{field}")

        for value in ("", [], ["s3:GetObject", ""], ["s3:GetObject", None]):
            with self.subTest(value=value):
                self.assert_rejected(make_policy({
                    "Effect": "Allow",
                    "Action": value,
                    "Resource": "*",
                }), "Action")

    def test_invalid_version_and_permission_field_types_are_rejected(self):
        self.assert_rejected(make_policy(Version=None), "Version")
        self.assert_rejected(make_policy({
            "Effect": "Allow",
            "Action": {"s3": "GetObject"},
            "Resource": "*",
        }), "Action")

    def test_identity_policy_and_statement_unsupported_fields_are_rejected(self):
        self.assert_rejected(make_policy(Id="policy-id"), "Id")
        self.assert_rejected(make_policy(Principal="*"), "Principal")
        self.assert_rejected(make_policy(Unexpected="value"), "Unexpected")

        for field in ("Principal", "NotPrincipal", "Unexpected"):
            with self.subTest(field=field):
                self.assert_rejected(make_policy({
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    field: "*",
                }), f"Statement[0].{field}")

    def test_non_string_api_input_returns_failure_result(self):
        self.assert_rejected(None, "JSON string")


if __name__ == "__main__":
    unittest.main()
