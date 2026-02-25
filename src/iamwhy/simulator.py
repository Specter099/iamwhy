"""Wrapper around IAM SimulatePrincipalPolicy API."""
from __future__ import annotations

from botocore.exceptions import ClientError

from .models import SimulationResult


class SimulationError(Exception):
    """Raised for unrecoverable AWS-side simulation failures."""

    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


def simulate(
    principal_arn: str,
    action: str,
    resource: str,
    context_entries: list[dict],
    iam_client,
) -> SimulationResult:
    """
    Call SimulatePrincipalPolicy for exactly one *action* and return a
    SimulationResult.

    Uses the boto3 paginator so large result sets are handled transparently.

    Raises:
        ValueError: principal not found or invalid input (user-fixable).
        SimulationError: AWS-side failure (credentials, service error).
    """
    try:
        paginator = iam_client.get_paginator("simulate_principal_policy")
        page_iter = paginator.paginate(
            PolicySourceArn=principal_arn,
            ActionNames=[action],
            ResourceArns=[resource],
            ContextEntries=context_entries,
        )
        eval_results: list[dict] = []
        for page in page_iter:
            eval_results.extend(page.get("EvaluationResults", []))
    except ClientError as exc:
        _handle_client_error(exc)

    if not eval_results:
        raise SimulationError(
            f"SimulatePrincipalPolicy returned no results for action {action!r}.",
            error_code="EmptyResults",
        )

    # We requested exactly one action; the first result is the one we want.
    r = eval_results[0]

    orgs_allowed: bool | None = None
    orgs_detail = r.get("OrganizationsDecisionDetail")
    if orgs_detail is not None:
        orgs_allowed = orgs_detail.get("AllowedByOrganizations")

    boundary_allowed: bool | None = None
    boundary_detail = r.get("PermissionsBoundaryDecisionDetail")
    if boundary_detail is not None:
        boundary_allowed = boundary_detail.get("AllowedByPermissionsBoundary")

    return SimulationResult(
        principal_arn=principal_arn,
        action=r.get("EvalActionName", action),
        resource=r.get("EvalResourceName", resource),
        eval_decision=r.get("EvalDecision", "implicitDeny"),
        matched_statements=tuple(r.get("MatchedStatements", [])),
        eval_decision_details=dict(r.get("EvalDecisionDetails", {})),
        missing_context_values=tuple(r.get("MissingContextValues", [])),
        orgs_allowed=orgs_allowed,
        boundary_allowed=boundary_allowed,
    )


def build_context_entries(raw_pairs: list[str]) -> list[dict]:
    """
    Parse a list of ``KEY=VALUE`` strings into ContextEntries dicts for
    SimulatePrincipalPolicy.

    All values default to ContextKeyType ``"string"``.

    Raises:
        ValueError: if any entry is missing the ``=`` separator.
    """
    entries: list[dict] = []
    for pair in raw_pairs:
        if "=" not in pair:
            raise ValueError(
                f"Invalid context entry {pair!r}: expected KEY=VALUE format."
            )
        key, value = pair.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(
                f"Invalid context entry {pair!r}: key cannot be empty."
            )
        entries.append(
            {
                "ContextKeyName": key,
                "ContextKeyValues": [value],
                "ContextKeyType": "string",
            }
        )
    return entries


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _handle_client_error(exc: ClientError) -> None:
    code = exc.response["Error"]["Code"]
    msg = exc.response["Error"]["Message"]
    if code == "NoSuchEntity":
        raise ValueError(f"Principal not found: {msg}") from exc
    if code == "InvalidInput":
        raise ValueError(f"Invalid simulation input: {msg}") from exc
    raise SimulationError(message=msg, error_code=code) from exc
