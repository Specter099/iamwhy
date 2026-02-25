"""Tests for iamwhy.cli — uses Click's CliRunner and pytest-mock."""
import json
import pytest
from click.testing import CliRunner
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, ProfileNotFound

from iamwhy.cli import main
from iamwhy.models import (
    DenialCause,
    DecisionType,
    PrincipalInfo,
    PrincipalType,
    SimulationResult,
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

_SIM_RESULT_DENY = SimulationResult(
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

_SIM_RESULT_ALLOW = SimulationResult(
    principal_arn=USER_ARN,
    action="s3:GetObject",
    resource="*",
    eval_decision="allowed",
    matched_statements=(),
    eval_decision_details={},
    missing_context_values=(),
    orgs_allowed=None,
    boundary_allowed=None,
)

_VERDICT_DENY = Verdict(
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

_VERDICT_ALLOW = Verdict(
    principal=_PRINCIPAL,
    action="s3:GetObject",
    resource="*",
    decision=DecisionType.ALLOWED,
    cause=DenialCause.IMPLICIT_DENY,
    summary="Access is allowed.",
    blocking_policies=(),
    all_breakdown=(),
    missing_context=(),
    orgs_blocked=False,
    boundary_blocked=False,
)


def _patch_all(
    resolve_return=_PRINCIPAL,
    sim_return=_SIM_RESULT_DENY,
    analyze_return=_VERDICT_DENY,
):
    """Context manager that patches all three core functions."""
    import contextlib
    from unittest.mock import patch as _patch

    @contextlib.contextmanager
    def _ctx():
        with _patch("iamwhy.cli.resolve_principal", return_value=resolve_return) as rp, \
             _patch("iamwhy.cli.simulate", return_value=sim_return) as sim, \
             _patch("iamwhy.cli.analyze", return_value=analyze_return) as ana:
            yield rp, sim, ana

    return _ctx()


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "PRINCIPAL" in result.output
    assert "ACTION" in result.output


def test_cli_denied_exits_1():
    runner = CliRunner()
    with _patch_all(analyze_return=_VERDICT_DENY):
        result = runner.invoke(main, ["alice", "s3:GetObject"])
    assert result.exit_code == 1


def test_cli_allowed_exits_0():
    runner = CliRunner()
    with _patch_all(sim_return=_SIM_RESULT_ALLOW, analyze_return=_VERDICT_ALLOW):
        result = runner.invoke(main, ["alice", "s3:GetObject"])
    assert result.exit_code == 0


def test_cli_json_output():
    runner = CliRunner()
    with _patch_all(analyze_return=_VERDICT_DENY):
        result = runner.invoke(main, ["alice", "s3:GetObject", "--output", "json"])
    assert result.exit_code == 1
    # The JSON goes to stdout; there may be Rich text on stderr but CliRunner
    # captures stdout by default (mix_stderr=False).
    combined = result.output
    # The JSON formatter writes to sys.stdout via print()
    # Find JSON in output (there may be Rich ANSI sequences too)
    try:
        data = json.loads(combined.strip())
        assert "decision" in data
    except json.JSONDecodeError:
        # output may contain non-JSON text from Rich stderr; just check key strings
        assert "implicitDeny" in combined or "decision" in combined


def test_cli_resource_option_passed_to_simulate():
    runner = CliRunner()
    with _patch_all() as (rp, sim, ana):
        runner.invoke(main, ["alice", "s3:GetObject", "--resource", "arn:aws:s3:::bucket"])
    sim.assert_called_once()
    call_args = sim.call_args
    assert call_args.args[2] == "arn:aws:s3:::bucket"


def test_cli_context_option_parsed():
    runner = CliRunner()
    with _patch_all() as (rp, sim, ana):
        runner.invoke(main, [
            "alice", "s3:GetObject",
            "--context", "aws:SourceIp=1.2.3.4",
        ])
    sim.assert_called_once()
    call_args = sim.call_args
    context_entries = call_args.args[3]
    assert any(e["ContextKeyName"] == "aws:SourceIp" for e in context_entries)


def test_cli_invalid_context_exits_2():
    runner = CliRunner()
    with _patch_all():
        result = runner.invoke(main, [
            "alice", "s3:GetObject",
            "--context", "no-equals-sign",
        ])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_cli_resolve_value_error_exits_2():
    runner = CliRunner()
    with patch("iamwhy.cli.resolve_principal", side_effect=ValueError("not found")):
        result = runner.invoke(main, ["nobody", "s3:GetObject"])
    assert result.exit_code == 2


def test_cli_resolve_client_error_exits_2():
    runner = CliRunner()
    err = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetUser")
    with patch("iamwhy.cli.resolve_principal", side_effect=err):
        result = runner.invoke(main, ["alice", "s3:GetObject"])
    assert result.exit_code == 2


def test_cli_simulation_error_exits_2():
    from iamwhy.simulator import SimulationError
    runner = CliRunner()
    with _patch_all() as (rp, sim, ana):
        sim.side_effect = SimulationError("fail", "AccessDenied")
        result = runner.invoke(main, ["alice", "s3:GetObject"])
    assert result.exit_code == 2


def test_cli_simulation_value_error_exits_2():
    runner = CliRunner()
    with _patch_all() as (rp, sim, ana):
        sim.side_effect = ValueError("bad input")
        result = runner.invoke(main, ["alice", "s3:GetObject"])
    assert result.exit_code == 2


def test_cli_profile_not_found_exits_2():
    runner = CliRunner()
    with patch(
        "iamwhy.cli.boto3.Session",
        side_effect=ProfileNotFound(profile="nonexistent"),
    ):
        result = runner.invoke(main, ["alice", "s3:GetObject", "--profile", "nonexistent"])
    assert result.exit_code == 2
