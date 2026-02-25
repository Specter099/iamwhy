"""Tests for iamwhy.simulator."""

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from iamwhy.simulator import SimulationError, build_context_entries, simulate

ACCOUNT = "123456789012"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/alice"
_TRUST = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
)
_ALLOW_S3 = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
)


# ---------------------------------------------------------------------------
# build_context_entries — pure unit tests
# ---------------------------------------------------------------------------


def test_build_context_entries_basic():
    result = build_context_entries(["aws:SourceIp=1.2.3.4"])
    assert result == [
        {
            "ContextKeyName": "aws:SourceIp",
            "ContextKeyValues": ["1.2.3.4"],
            "ContextKeyType": "string",
        }
    ]


def test_build_context_entries_multiple():
    result = build_context_entries(
        ["aws:SourceIp=10.0.0.1", "aws:MultiFactorAuthPresent=true"]
    )
    assert len(result) == 2
    assert result[1]["ContextKeyName"] == "aws:MultiFactorAuthPresent"
    assert result[1]["ContextKeyValues"] == ["true"]


def test_build_context_entries_empty_list():
    assert build_context_entries([]) == []


def test_build_context_entries_value_with_equals():
    # Values that contain '=' should be preserved intact
    result = build_context_entries(["aws:RequestedRegion=us=east=1"])
    assert result[0]["ContextKeyValues"] == ["us=east=1"]


def test_build_context_entries_missing_equals_raises():
    with pytest.raises(ValueError, match="KEY=VALUE"):
        build_context_entries(["no-separator-here"])


def test_build_context_entries_empty_key_raises():
    with pytest.raises(ValueError, match="key cannot be empty"):
        build_context_entries(["=value"])


# ---------------------------------------------------------------------------
# simulate() — moto + pytest-mock
# ---------------------------------------------------------------------------


def _mock_iam_with_result(eval_result: dict):
    """Return a mock IAM client whose paginator yields one page with eval_result."""
    mock_page_iter = MagicMock()
    mock_page_iter.__iter__ = MagicMock(
        return_value=iter([{"EvaluationResults": [eval_result]}])
    )
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = mock_page_iter
    mock_client = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator
    return mock_client


def test_simulate_implicit_deny():
    """Injected implicitDeny response is returned correctly."""
    mock_iam = _mock_iam_with_result(
        {
            "EvalActionName": "s3:GetObject",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "EvalDecisionDetails": {},
            "MissingContextValues": [],
        }
    )
    result = simulate(USER_ARN, "s3:GetObject", "*", [], mock_iam)
    assert result.eval_decision == "implicitDeny"
    assert result.action == "s3:GetObject"
    assert result.principal_arn == USER_ARN


def test_simulate_allowed():
    """Injected 'allowed' response is returned correctly."""
    mock_iam = _mock_iam_with_result(
        {
            "EvalActionName": "s3:GetObject",
            "EvalResourceName": "*",
            "EvalDecision": "allowed",
            "MatchedStatements": [
                {"SourcePolicyId": "S3Full", "SourcePolicyType": "IAMPolicy"}
            ],
            "EvalDecisionDetails": {"S3Full": "allowed"},
            "MissingContextValues": [],
        }
    )
    result = simulate(USER_ARN, "s3:GetObject", "*", [], mock_iam)
    assert result.eval_decision == "allowed"
    assert "S3Full" in result.eval_decision_details


def test_simulate_missing_context_values_populated():
    """MissingContextValues is surfaced as a tuple."""
    mock_iam = _mock_iam_with_result(
        {
            "EvalActionName": "s3:GetObject",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "EvalDecisionDetails": {},
            "MissingContextValues": ["aws:RequestedRegion"],
        }
    )
    result = simulate(USER_ARN, "s3:GetObject", "*", [], mock_iam)
    assert "aws:RequestedRegion" in result.missing_context_values


def test_simulate_returns_simulation_result_type():
    from iamwhy.models import SimulationResult

    mock_iam = _mock_iam_with_result(
        {
            "EvalActionName": "ec2:DescribeInstances",
            "EvalResourceName": "*",
            "EvalDecision": "implicitDeny",
            "MatchedStatements": [],
            "EvalDecisionDetails": {},
            "MissingContextValues": [],
        }
    )
    result = simulate(USER_ARN, "ec2:DescribeInstances", "*", [], mock_iam)
    assert isinstance(result, SimulationResult)


# ---------------------------------------------------------------------------
# Error handling — pytest-mock (inject ClientError without real AWS)
# ---------------------------------------------------------------------------


def _make_client_error(code: str, message: str = "msg") -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}}, "SimulatePrincipalPolicy"
    )


def _make_mock_iam(error: ClientError):
    """Return a mock IAM client whose paginator raises the given error."""
    mock_page_iter = MagicMock()
    mock_page_iter.__iter__ = MagicMock(side_effect=error)
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = mock_page_iter
    mock_client = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator
    return mock_client


def test_simulate_no_such_entity_raises_value_error():
    mock_iam = _make_mock_iam(_make_client_error("NoSuchEntity", "User not found"))
    with pytest.raises(ValueError, match="Principal not found"):
        simulate(USER_ARN, "s3:GetObject", "*", [], mock_iam)


def test_simulate_invalid_input_raises_value_error():
    mock_iam = _make_mock_iam(_make_client_error("InvalidInput", "Bad action"))
    with pytest.raises(ValueError, match="Invalid simulation input"):
        simulate(USER_ARN, "s3:invalid-action", "*", [], mock_iam)


def test_simulate_access_denied_raises_simulation_error():
    mock_iam = _make_mock_iam(_make_client_error("AccessDenied", "Not allowed"))
    with pytest.raises(SimulationError) as exc_info:
        simulate(USER_ARN, "s3:GetObject", "*", [], mock_iam)
    assert exc_info.value.error_code == "AccessDenied"


def test_simulate_service_failure_raises_simulation_error():
    mock_iam = _make_mock_iam(_make_client_error("ServiceFailure", "Internal"))
    with pytest.raises(SimulationError) as exc_info:
        simulate(USER_ARN, "s3:GetObject", "*", [], mock_iam)
    assert exc_info.value.error_code == "ServiceFailure"


def test_simulate_empty_results_raises_simulation_error():
    mock_page_iter = MagicMock()
    mock_page_iter.__iter__ = MagicMock(return_value=iter([{"EvaluationResults": []}]))
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = mock_page_iter
    mock_client = MagicMock()
    mock_client.get_paginator.return_value = mock_paginator

    with pytest.raises(SimulationError, match="no results"):
        simulate(USER_ARN, "s3:GetObject", "*", [], mock_client)
