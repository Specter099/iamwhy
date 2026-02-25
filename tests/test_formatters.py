"""Tests for iamwhy.formatters."""

import json

from rich.console import Console

from iamwhy.formatters import JsonFormatter, TextFormatter, get_formatter
from iamwhy.models import (
    DecisionType,
    DenialCause,
    PolicyBreakdown,
    PolicySource,
    PrincipalInfo,
    PrincipalType,
    Verdict,
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


def _make_verdict(**kwargs) -> Verdict:
    defaults = dict(
        principal=_PRINCIPAL,
        action="s3:GetObject",
        resource="*",
        decision=DecisionType.IMPLICIT_DENY,
        cause=DenialCause.IMPLICIT_DENY,
        summary="No policy grants the requested action.",
        blocking_policies=(),
        all_breakdown=(),
        missing_context=(),
        orgs_blocked=False,
        boundary_blocked=False,
    )
    defaults.update(kwargs)
    return Verdict(**defaults)


def _record_console() -> Console:
    """Return a Console that records output for later inspection."""
    return Console(record=True, highlight=False, width=120)


# ---------------------------------------------------------------------------
# TextFormatter
# ---------------------------------------------------------------------------


def test_text_formatter_allowed_verdict():
    console = _record_console()
    verdict = _make_verdict(
        decision=DecisionType.ALLOWED,
        cause=DenialCause.IMPLICIT_DENY,
        summary="Access is allowed.",
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "ALLOWED" in output
    assert "alice" in output


def test_text_formatter_explicit_deny_label():
    console = _record_console()
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        summary="Explicit deny.",
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "DENIED" in output
    assert "explicit deny" in output.lower()


def test_text_formatter_implicit_deny_label():
    console = _record_console()
    verdict = _make_verdict()
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "DENIED" in output
    assert "implicit deny" in output.lower()


def test_text_formatter_shows_action_and_resource():
    console = _record_console()
    verdict = _make_verdict(action="ec2:DescribeInstances", resource="arn:aws:ec2:::*")
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "ec2:DescribeInstances" in output
    assert "arn:aws:ec2:::*" in output


def test_text_formatter_shows_missing_context():
    console = _record_console()
    verdict = _make_verdict(
        missing_context=("aws:SourceVpc", "aws:SourceIp"),
        cause=DenialCause.MISSING_CONTEXT,
        summary="Missing context keys.",
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "aws:SourceVpc" in output


def test_text_formatter_no_missing_context_shows_none():
    console = _record_console()
    verdict = _make_verdict()
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "(none)" in output


def test_text_formatter_blocking_policy_with_source():
    src = PolicySource(
        policy_id="arn:aws:iam::123:policy/DenyAll",
        policy_type="IAMPolicy",
        effect="Deny",
        actions=("s3:*",),
        resources=("*",),
        sid="DenyS3",
        raw_statement={
            "Sid": "DenyS3",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
        },
    )
    bp = PolicyBreakdown(
        policy_id="arn:aws:iam::123:policy/DenyAll",
        decision="explicitDeny",
        source=src,
    )
    console = _record_console()
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        blocking_policies=(bp,),
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "DenyS3" in output or "Deny" in output


def test_text_formatter_blocking_policy_no_statement():
    bp = PolicyBreakdown(
        policy_id="arn:aws:iam::123:policy/SomePolicy",
        decision="explicitDeny",
        source=PolicySource(
            policy_id="arn:aws:iam::123:policy/SomePolicy",
            policy_type="IAMPolicy",
            effect=None,
            actions=(),
            resources=(),
            sid=None,
            raw_statement=None,
        ),
    )
    console = _record_console()
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        blocking_policies=(bp,),
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "unavailable" in output or "insufficient" in output


def test_text_formatter_decision_breakdown_table():
    breakdown = (
        PolicyBreakdown(policy_id="PolicyA", decision="explicitDeny"),
        PolicyBreakdown(policy_id="PolicyB", decision="allowed"),
    )
    console = _record_console()
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        all_breakdown=breakdown,
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "PolicyA" in output
    assert "PolicyB" in output


def test_text_formatter_orgs_note():
    console = _record_console()
    verdict = _make_verdict(orgs_blocked=True, cause=DenialCause.SCP_BLOCK)
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "SCP" in output or "organization" in output.lower()


def test_text_formatter_boundary_note():
    console = _record_console()
    verdict = _make_verdict(
        boundary_blocked=True, cause=DenialCause.PERMISSIONS_BOUNDARY
    )
    TextFormatter(console=console).render(verdict)
    output = console.export_text()
    assert "boundary" in output.lower()


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------


def _capture_json(verdict: Verdict) -> dict:
    """Capture JsonFormatter output by monkeypatching print."""
    captured: list[str] = []
    import builtins

    original_print = builtins.print

    def fake_print(*args, **kwargs):
        captured.append(" ".join(str(a) for a in args))

    builtins.print = fake_print
    try:
        JsonFormatter().render(verdict)
    finally:
        builtins.print = original_print

    return json.loads("\n".join(captured))


def test_json_formatter_valid_json():
    verdict = _make_verdict()
    data = _capture_json(verdict)
    assert isinstance(data, dict)


def test_json_formatter_required_keys():
    verdict = _make_verdict()
    data = _capture_json(verdict)
    required = {
        "principal",
        "principal_type",
        "action",
        "resource",
        "decision",
        "cause",
        "summary",
        "orgs_blocked",
        "boundary_blocked",
        "missing_context",
        "blocking_policies",
        "all_breakdown",
    }
    assert required.issubset(data.keys())


def test_json_formatter_decision_value():
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY, cause=DenialCause.EXPLICIT_DENY
    )
    data = _capture_json(verdict)
    assert data["decision"] == "explicitDeny"
    assert data["cause"] == "explicit_deny"


def test_json_formatter_blocking_policies_with_statement():
    src = PolicySource(
        policy_id="arn:aws:iam::123:policy/P",
        policy_type="IAMPolicy",
        effect="Deny",
        actions=("s3:*",),
        resources=("*",),
        sid="DenyAll",
        raw_statement={
            "Sid": "DenyAll",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
        },
    )
    bp = PolicyBreakdown(
        policy_id="arn:aws:iam::123:policy/P", decision="explicitDeny", source=src
    )
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        blocking_policies=(bp,),
    )
    data = _capture_json(verdict)
    assert len(data["blocking_policies"]) == 1
    assert data["blocking_policies"][0]["statement"]["Sid"] == "DenyAll"


def test_json_formatter_null_statement_when_no_source():
    bp = PolicyBreakdown(policy_id="SomePolicy", decision="explicitDeny", source=None)
    verdict = _make_verdict(
        decision=DecisionType.EXPLICIT_DENY,
        cause=DenialCause.EXPLICIT_DENY,
        blocking_policies=(bp,),
    )
    data = _capture_json(verdict)
    assert data["blocking_policies"][0]["statement"] is None


# ---------------------------------------------------------------------------
# get_formatter factory
# ---------------------------------------------------------------------------


def test_get_formatter_text():
    f = get_formatter("text")
    assert isinstance(f, TextFormatter)


def test_get_formatter_json():
    f = get_formatter("json")
    assert isinstance(f, JsonFormatter)


def test_get_formatter_text_with_custom_console():
    console = _record_console()
    f = get_formatter("text", console=console)
    assert isinstance(f, TextFormatter)
    assert f.console is console
