"""Tests for iamwhy.models — pure data, no AWS calls."""
import dataclasses
import pytest

from iamwhy.models import (
    DenialCause,
    DecisionType,
    PolicyBreakdown,
    PolicySource,
    PrincipalInfo,
    PrincipalType,
    SimulationResult,
    Verdict,
)


# ---------------------------------------------------------------------------
# PrincipalInfo
# ---------------------------------------------------------------------------

def test_principal_info_frozen():
    p = PrincipalInfo(
        arn="arn:aws:iam::123456789012:user/alice",
        principal_type=PrincipalType.USER,
        account_id="123456789012",
        name="alice",
        session_name=None,
        raw_input="alice",
    )
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        p.name = "bob"  # type: ignore[misc]


def test_principal_info_assumed_role_session_name():
    p = PrincipalInfo(
        arn="arn:aws:iam::123456789012:role/MyRole",
        principal_type=PrincipalType.ASSUMED_ROLE,
        account_id="123456789012",
        name="MyRole",
        session_name="my-session",
        raw_input="arn:aws:sts::123456789012:assumed-role/MyRole/my-session",
    )
    assert p.session_name == "my-session"
    assert p.principal_type == PrincipalType.ASSUMED_ROLE


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

def test_decision_type_values():
    assert DecisionType.ALLOWED.value == "allowed"
    assert DecisionType.EXPLICIT_DENY.value == "explicitDeny"
    assert DecisionType.IMPLICIT_DENY.value == "implicitDeny"


def test_denial_cause_values():
    assert DenialCause.EXPLICIT_DENY.value == "explicit_deny"
    assert DenialCause.IMPLICIT_DENY.value == "implicit_deny"
    assert DenialCause.SCP_BLOCK.value == "scp_block"
    assert DenialCause.PERMISSIONS_BOUNDARY.value == "permissions_boundary"
    assert DenialCause.MISSING_CONTEXT.value == "missing_context"
    assert DenialCause.COMBINED.value == "combined"


def test_principal_type_values():
    assert PrincipalType.USER.value == "user"
    assert PrincipalType.ROLE.value == "role"
    assert PrincipalType.ASSUMED_ROLE.value == "assumed-role"


# ---------------------------------------------------------------------------
# SimulationResult
# ---------------------------------------------------------------------------

def test_simulation_result_frozen():
    r = SimulationResult(
        principal_arn="arn:aws:iam::123456789012:user/alice",
        action="s3:GetObject",
        resource="*",
        eval_decision="implicitDeny",
        matched_statements=(),
        eval_decision_details={},
        missing_context_values=(),
        orgs_allowed=None,
        boundary_allowed=None,
    )
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        r.eval_decision = "allowed"  # type: ignore[misc]


def test_simulation_result_defaults():
    r = SimulationResult(
        principal_arn="arn:aws:iam::123456789012:role/R",
        action="ec2:DescribeInstances",
        resource="*",
        eval_decision="allowed",
        matched_statements=(),
        eval_decision_details={},
        missing_context_values=(),
        orgs_allowed=None,
        boundary_allowed=None,
    )
    assert r.orgs_allowed is None
    assert r.boundary_allowed is None
    assert r.missing_context_values == ()


# ---------------------------------------------------------------------------
# PolicyBreakdown
# ---------------------------------------------------------------------------

def test_policy_breakdown_source_optional():
    b = PolicyBreakdown(policy_id="arn:aws:iam::aws:policy/ReadOnlyAccess", decision="allowed")
    assert b.source is None


def test_policy_breakdown_with_source():
    src = PolicySource(
        policy_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
        policy_type="aws-managed",
        effect="Allow",
        actions=("s3:GetObject",),
        resources=("*",),
        sid="ReadS3",
        raw_statement={"Sid": "ReadS3", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    )
    b = PolicyBreakdown(
        policy_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
        decision="allowed",
        source=src,
    )
    assert b.source is not None
    assert b.source.effect == "Allow"


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def _make_principal() -> PrincipalInfo:
    return PrincipalInfo(
        arn="arn:aws:iam::123456789012:user/alice",
        principal_type=PrincipalType.USER,
        account_id="123456789012",
        name="alice",
        session_name=None,
        raw_input="alice",
    )


def test_verdict_construction_minimal():
    v = Verdict(
        principal=_make_principal(),
        action="s3:GetObject",
        resource="*",
        decision=DecisionType.IMPLICIT_DENY,
        cause=DenialCause.IMPLICIT_DENY,
        summary="No policy allows s3:GetObject.",
        blocking_policies=(),
        all_breakdown=(),
        missing_context=(),
        orgs_blocked=False,
        boundary_blocked=False,
    )
    assert v.decision == DecisionType.IMPLICIT_DENY
    assert v.blocking_policies == ()


def test_verdict_frozen():
    v = Verdict(
        principal=_make_principal(),
        action="s3:GetObject",
        resource="*",
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        summary="Explicit deny.",
        blocking_policies=(),
        all_breakdown=(),
        missing_context=(),
        orgs_blocked=False,
        boundary_blocked=False,
    )
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        v.action = "s3:PutObject"  # type: ignore[misc]
