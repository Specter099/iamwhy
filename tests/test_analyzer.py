"""Tests for iamwhy.analyzer — all use pre-built SimulationResult fixtures, no moto."""
import pytest
from unittest.mock import MagicMock, call
from botocore.exceptions import ClientError

from iamwhy.analyzer import analyze
from iamwhy.models import (
    DenialCause,
    DecisionType,
    PrincipalInfo,
    PrincipalType,
    SimulationResult,
)

ACCOUNT = "123456789012"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/alice"

_PRINCIPAL = PrincipalInfo(
    arn=USER_ARN,
    principal_type=PrincipalType.USER,
    account_id=ACCOUNT,
    name="alice",
    session_name=None,
    raw_input="alice",
)


def _make_result(**kwargs) -> SimulationResult:
    defaults = dict(
        principal_arn=USER_ARN,
        action="s3:GetObject",
        resource="*",
        eval_decision="implicitDeny",
        matched_statements=(),
        eval_decision_details={},
        missing_context_values=(),
        orgs_allowed=None,
        boundary_allowed=None,
    )
    defaults.update(kwargs)
    return SimulationResult(**defaults)


def _mock_iam():
    """Return a mock IAM client that raises NotImplementedError on any call."""
    m = MagicMock()
    m.get_policy.side_effect = NotImplementedError("should not be called")
    return m


# ---------------------------------------------------------------------------
# Decision type mapping
# ---------------------------------------------------------------------------

def test_analyze_allowed():
    result = _make_result(eval_decision="allowed")
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.decision == DecisionType.ALLOWED
    assert verdict.cause == DenialCause.IMPLICIT_DENY  # cause irrelevant for allowed


def test_analyze_explicit_deny():
    result = _make_result(
        eval_decision="explicitDeny",
        eval_decision_details={"DenyPolicy": "explicitDeny"},
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.decision == DecisionType.EXPLICIT_DENY
    assert verdict.cause == DenialCause.EXPLICIT_DENY


def test_analyze_implicit_deny():
    result = _make_result(eval_decision="implicitDeny")
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.decision == DecisionType.IMPLICIT_DENY
    assert verdict.cause == DenialCause.IMPLICIT_DENY


# ---------------------------------------------------------------------------
# Cause determination
# ---------------------------------------------------------------------------

def test_analyze_scp_block():
    result = _make_result(eval_decision="implicitDeny", orgs_allowed=False)
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.cause == DenialCause.SCP_BLOCK
    assert verdict.orgs_blocked is True


def test_analyze_permissions_boundary():
    result = _make_result(eval_decision="implicitDeny", boundary_allowed=False)
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.cause == DenialCause.PERMISSIONS_BOUNDARY
    assert verdict.boundary_blocked is True


def test_analyze_missing_context():
    result = _make_result(
        eval_decision="implicitDeny",
        missing_context_values=("aws:RequestedRegion",),
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.cause == DenialCause.MISSING_CONTEXT
    assert "aws:RequestedRegion" in verdict.missing_context


def test_analyze_combined_scp_and_explicit_deny():
    result = _make_result(
        eval_decision="explicitDeny",
        orgs_allowed=False,
        eval_decision_details={"DenyPolicy": "explicitDeny"},
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.cause == DenialCause.COMBINED


def test_analyze_combined_boundary_and_explicit_deny():
    result = _make_result(
        eval_decision="explicitDeny",
        boundary_allowed=False,
        eval_decision_details={"DenyPolicy": "explicitDeny"},
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.cause == DenialCause.COMBINED


# ---------------------------------------------------------------------------
# Summary text sanity checks
# ---------------------------------------------------------------------------

def test_summary_explicit_deny_mentions_policy():
    result = _make_result(
        eval_decision="explicitDeny",
        eval_decision_details={"arn:aws:iam::123:policy/DenyAll": "explicitDeny"},
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert "Deny" in verdict.summary or "deny" in verdict.summary.lower()


def test_summary_implicit_deny():
    result = _make_result(eval_decision="implicitDeny")
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert "No policy" in verdict.summary or "default deny" in verdict.summary.lower()


def test_summary_allowed():
    result = _make_result(eval_decision="allowed")
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert "allowed" in verdict.summary.lower()


def test_summary_missing_context_mentions_key():
    result = _make_result(
        eval_decision="implicitDeny",
        missing_context_values=("aws:SourceVpc",),
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert "aws:SourceVpc" in verdict.summary


def test_summary_scp_block():
    result = _make_result(eval_decision="implicitDeny", orgs_allowed=False)
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert "SCP" in verdict.summary or "Organizations" in verdict.summary


def test_summary_permissions_boundary():
    result = _make_result(eval_decision="implicitDeny", boundary_allowed=False)
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert "boundary" in verdict.summary.lower()


# ---------------------------------------------------------------------------
# fetch_statements=False skips all GetPolicy calls
# ---------------------------------------------------------------------------

def test_fetch_statements_false_no_api_calls():
    mock_iam = MagicMock()
    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": "MyPolicy", "SourcePolicyType": "IAMPolicy"},
        ),
    )
    analyze(result, _PRINCIPAL, mock_iam, fetch_statements=False)
    mock_iam.get_policy.assert_not_called()
    mock_iam.get_policy_version.assert_not_called()


# ---------------------------------------------------------------------------
# Graceful degradation: ClientError on GetPolicyVersion → raw_statement=None
# ---------------------------------------------------------------------------

def test_fetch_statements_client_error_degrades_gracefully():
    mock_iam = MagicMock()
    mock_iam.get_policy.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}},
        "GetPolicy",
    )
    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": "arn:aws:iam::123:policy/P", "SourcePolicyType": "IAMPolicy"},
        ),
    )
    verdict = analyze(result, _PRINCIPAL, mock_iam, fetch_statements=True)
    # Should not raise; raw_statement should be None for the affected policy
    for bp in verdict.blocking_policies:
        if bp.source is not None:
            assert bp.source.raw_statement is None


# ---------------------------------------------------------------------------
# Verdict fields are consistent
# ---------------------------------------------------------------------------

def test_verdict_principal_passthrough():
    result = _make_result(eval_decision="implicitDeny")
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.principal is _PRINCIPAL
    assert verdict.action == "s3:GetObject"
    assert verdict.resource == "*"


def test_verdict_all_breakdown_populated():
    result = _make_result(
        eval_decision="explicitDeny",
        eval_decision_details={
            "arn:aws:iam::aws:policy/ReadOnly": "allowed",
            "arn:aws:iam::123:policy/DenyAll": "explicitDeny",
        },
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    ids = {b.policy_id for b in verdict.all_breakdown}
    assert "arn:aws:iam::aws:policy/ReadOnly" in ids
    assert "arn:aws:iam::123:policy/DenyAll" in ids


# ---------------------------------------------------------------------------
# COMBINED summary text
# ---------------------------------------------------------------------------

def test_summary_combined_mentions_factors():
    result = _make_result(
        eval_decision="explicitDeny",
        orgs_allowed=False,
        eval_decision_details={"DenyPolicy": "explicitDeny"},
    )
    verdict = analyze(result, _PRINCIPAL, _mock_iam(), fetch_statements=False)
    assert verdict.cause == DenialCause.COMBINED
    assert "multiple factors" in verdict.summary.lower() or "SCP" in verdict.summary or "deny" in verdict.summary.lower()


# ---------------------------------------------------------------------------
# Statement retrieval — fetch_statements=True with moto
# ---------------------------------------------------------------------------

_POLICY_DOC_DENY = (
    '{"Version":"2012-10-17","Statement":[{"Sid":"DenyS3","Effect":"Deny",'
    '"Action":"s3:*","Resource":"*"}]}'
)
_INLINE_DOC = (
    '{"Version":"2012-10-17","Statement":[{"Sid":"InlineDeny","Effect":"Deny",'
    '"Action":["ec2:TerminateInstances"],"Resource":"*"}]}'
)
_TRUST = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
)


def test_fetch_statements_managed_policy(moto_iam):
    pol = moto_iam.create_policy(PolicyName="DenyAll", PolicyDocument=_POLICY_DOC_DENY)
    pol_arn = pol["Policy"]["Arn"]

    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": pol_arn, "SourcePolicyType": "IAMPolicy"},
        ),
    )
    verdict = analyze(result, _PRINCIPAL, moto_iam, fetch_statements=True)
    assert verdict.blocking_policies
    bp = verdict.blocking_policies[0]
    assert bp.source is not None
    assert bp.source.raw_statement is not None
    assert bp.source.effect == "Deny"
    assert bp.source.sid == "DenyS3"


def test_fetch_statements_unknown_policy_type_returns_empty_source():
    mock_iam = MagicMock()
    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": "SomePolicy", "SourcePolicyType": "ResourcePolicy"},
        ),
    )
    verdict = analyze(result, _PRINCIPAL, mock_iam, fetch_statements=True)
    # Should not raise; blocking_policies should still be populated
    assert verdict.blocking_policies
    bp = verdict.blocking_policies[0]
    # raw_statement is None for unknown types
    assert bp.source is None or bp.source.raw_statement is None


def test_fetch_statements_inline_user_policy(moto_iam):
    moto_iam.create_user(UserName="alice")
    moto_iam.put_user_policy(
        UserName="alice", PolicyName="InlineDeny", PolicyDocument=_INLINE_DOC
    )
    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": "InlineDeny", "SourcePolicyType": "User"},
        ),
    )
    verdict = analyze(result, _PRINCIPAL, moto_iam, fetch_statements=True)
    assert verdict.blocking_policies
    bp = verdict.blocking_policies[0]
    assert bp.source is not None
    assert bp.source.effect == "Deny"
    assert bp.source.sid == "InlineDeny"


def test_fetch_statements_inline_role_policy(moto_iam):
    moto_iam.create_role(RoleName="MyRole", AssumeRolePolicyDocument=_TRUST)
    moto_iam.put_role_policy(
        RoleName="MyRole", PolicyName="InlineDeny", PolicyDocument=_INLINE_DOC
    )
    role_principal = PrincipalInfo(
        arn=moto_iam.get_role(RoleName="MyRole")["Role"]["Arn"],
        principal_type=PrincipalType.ROLE,
        account_id=ACCOUNT,
        name="MyRole",
        session_name=None,
        raw_input="MyRole",
    )
    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": "InlineDeny", "SourcePolicyType": "Role"},
        ),
    )
    verdict = analyze(result, role_principal, moto_iam, fetch_statements=True)
    assert verdict.blocking_policies
    bp = verdict.blocking_policies[0]
    assert bp.source is not None
    assert bp.source.effect == "Deny"


# ---------------------------------------------------------------------------
# _normalize_list via fetch path
# ---------------------------------------------------------------------------

def test_normalize_list_string_action(moto_iam):
    """Policies with a single Action string (not list) are normalised correctly."""
    # The POLICY_DOC_DENY above has "Action":"s3:*" (string, not list)
    pol = moto_iam.create_policy(PolicyName="DenyAllStr", PolicyDocument=_POLICY_DOC_DENY)
    pol_arn = pol["Policy"]["Arn"]
    result = _make_result(
        eval_decision="explicitDeny",
        matched_statements=(
            {"SourcePolicyId": pol_arn, "SourcePolicyType": "IAMPolicy"},
        ),
    )
    verdict = analyze(result, _PRINCIPAL, moto_iam, fetch_statements=True)
    bp = verdict.blocking_policies[0]
    assert bp.source is not None
    # actions should be a tuple of strings
    assert isinstance(bp.source.actions, tuple)
    assert "s3:*" in bp.source.actions
