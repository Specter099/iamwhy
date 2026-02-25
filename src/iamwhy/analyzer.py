"""Interpret a SimulationResult into a human-readable Verdict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from .models import (
    DenialCause,
    DecisionType,
    PolicyBreakdown,
    PolicySource,
    PrincipalInfo,
    PrincipalType,
    SimulationResult,
    Verdict,
)


def analyze(
    result: SimulationResult,
    principal: PrincipalInfo,
    iam_client,
    fetch_statements: bool = True,
) -> Verdict:
    """
    Interpret *result* into a Verdict with a human-readable summary.

    If *fetch_statements* is True (default), the analyzer calls
    GetPolicy/GetPolicyVersion for each matched statement to populate
    PolicySource.raw_statement.  On any ClientError the field is left None
    (degraded mode — policy ID is still shown).
    """
    decision = _map_decision(result.eval_decision)

    # Build per-policy breakdown from EvalDecisionDetails
    all_breakdown = tuple(
        PolicyBreakdown(policy_id=pid, decision=dec)
        for pid, dec in result.eval_decision_details.items()
    )

    # Determine blocking policies (those with explicitDeny or the overall deny)
    blocking_policies = tuple(
        b for b in all_breakdown if b.decision == "explicitDeny"
    )

    # Optionally enrich blocking policies with statement text
    if fetch_statements and result.matched_statements:
        enriched = []
        for stmt in result.matched_statements:
            source = _fetch_policy_source(stmt, principal, iam_client)
            enriched.append(
                PolicyBreakdown(
                    policy_id=stmt.get("SourcePolicyId", "unknown"),
                    decision=result.eval_decision,
                    source=source,
                )
            )
        # Use enriched breakdown for blocking policies (deduped by policy_id)
        seen: set[str] = set()
        deduped = []
        for bp in enriched:
            if bp.policy_id not in seen:
                deduped.append(bp)
                seen.add(bp.policy_id)
        blocking_policies = tuple(deduped)

    orgs_blocked = result.orgs_allowed is False
    boundary_blocked = result.boundary_allowed is False

    cause = _determine_cause(
        eval_decision=result.eval_decision,
        missing_context=result.missing_context_values,
        orgs_blocked=orgs_blocked,
        boundary_blocked=boundary_blocked,
    )

    summary = _build_summary(
        decision=decision,
        cause=cause,
        blocking_policies=blocking_policies,
        missing_context=result.missing_context_values,
        orgs_blocked=orgs_blocked,
        boundary_blocked=boundary_blocked,
    )

    return Verdict(
        principal=principal,
        action=result.action,
        resource=result.resource,
        decision=decision,
        cause=cause,
        summary=summary,
        blocking_policies=blocking_policies,
        all_breakdown=all_breakdown,
        missing_context=result.missing_context_values,
        orgs_blocked=orgs_blocked,
        boundary_blocked=boundary_blocked,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _map_decision(raw: str) -> DecisionType:
    try:
        return DecisionType(raw)
    except ValueError:
        return DecisionType.IMPLICIT_DENY


def _determine_cause(
    *,
    eval_decision: str,
    missing_context: tuple[str, ...],
    orgs_blocked: bool,
    boundary_blocked: bool,
) -> DenialCause:
    active: list[DenialCause] = []

    if orgs_blocked:
        active.append(DenialCause.SCP_BLOCK)
    if boundary_blocked:
        active.append(DenialCause.PERMISSIONS_BOUNDARY)
    if missing_context and eval_decision == "implicitDeny":
        active.append(DenialCause.MISSING_CONTEXT)
    if eval_decision == "explicitDeny":
        active.append(DenialCause.EXPLICIT_DENY)
    if not active and eval_decision == "implicitDeny":
        active.append(DenialCause.IMPLICIT_DENY)

    if len(active) == 0:
        # 'allowed' case — cause doesn't matter
        return DenialCause.IMPLICIT_DENY
    if len(active) == 1:
        return active[0]
    return DenialCause.COMBINED


def _build_summary(
    *,
    decision: DecisionType,
    cause: DenialCause,
    blocking_policies: tuple[PolicyBreakdown, ...],
    missing_context: tuple[str, ...],
    orgs_blocked: bool = False,
    boundary_blocked: bool = False,
) -> str:
    if decision == DecisionType.ALLOWED:
        return "Access is allowed."

    policy_names = [bp.policy_id for bp in blocking_policies]
    policy_str = ", ".join(f'"{p}"' for p in policy_names) if policy_names else "an unknown policy"

    if cause == DenialCause.EXPLICIT_DENY:
        return f"An explicit Deny statement in {policy_str} overrides any Allow."
    if cause == DenialCause.IMPLICIT_DENY:
        return "No policy grants the requested action. The default deny applies."
    if cause == DenialCause.SCP_BLOCK:
        return (
            "An AWS Organizations Service Control Policy (SCP) denies this action "
            "for the account or organizational unit."
        )
    if cause == DenialCause.PERMISSIONS_BOUNDARY:
        return (
            "The principal's permissions boundary does not allow this action. "
            "Even if an identity policy grants access, the boundary blocks it."
        )
    if cause == DenialCause.MISSING_CONTEXT:
        keys = ", ".join(missing_context)
        return (
            f"Access could not be evaluated because required context key(s) are missing: {keys}. "
            "The simulation defaulted to deny."
        )
    # COMBINED — enumerate all active causes
    parts: list[str] = []
    if orgs_blocked:
        parts.append("an SCP")
    if boundary_blocked:
        parts.append("a permissions boundary")
    if any(bp.decision == "explicitDeny" for bp in blocking_policies):
        parts.append(f"an explicit deny in {policy_str}")
    if missing_context:
        parts.append("missing context keys")
    if not parts:
        parts.append("multiple policy factors")
    return "Access is denied by multiple factors: " + ", and ".join(parts) + "."


# ---------------------------------------------------------------------------
# Statement retrieval
# ---------------------------------------------------------------------------

def _fetch_policy_source(
    matched: dict,
    principal: PrincipalInfo,
    iam_client,
) -> PolicySource | None:
    """
    Resolve a MatchedStatement dict to a PolicySource with raw_statement.
    Returns None on any error.
    """
    policy_id: str = matched.get("SourcePolicyId", "")
    policy_type: str = matched.get("SourcePolicyType", "")

    try:
        if policy_type in ("IAMPolicy",):
            return _fetch_managed_policy_source(policy_id, iam_client)
        if policy_type in ("User", "Group", "Role"):
            return _fetch_inline_policy_source(policy_id, policy_type, principal, iam_client)
        # Unknown type — return a minimal source with no statement text
        return PolicySource(
            policy_id=policy_id,
            policy_type=policy_type,
            effect=None,
            actions=(),
            resources=(),
            sid=None,
            raw_statement=None,
        )
    except (ClientError, Exception):
        return PolicySource(
            policy_id=policy_id,
            policy_type=policy_type,
            effect=None,
            actions=(),
            resources=(),
            sid=None,
            raw_statement=None,
        )


def _fetch_managed_policy_source(policy_arn: str, iam_client) -> PolicySource:
    pol = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
    version_id = pol["DefaultVersionId"]
    version = iam_client.get_policy_version(
        PolicyArn=policy_arn, VersionId=version_id
    )["PolicyVersion"]
    document = version["Document"]
    statements = document.get("Statement", [])
    # Return the first statement as a representative (caller can inspect all)
    raw = statements[0] if statements else None
    effect = raw.get("Effect") if raw else None
    actions = _normalize_list(raw.get("Action", [])) if raw else ()
    resources = _normalize_list(raw.get("Resource", [])) if raw else ()
    sid = raw.get("Sid") if raw else None
    return PolicySource(
        policy_id=policy_arn,
        policy_type="IAMPolicy",
        effect=effect,
        actions=tuple(actions),
        resources=tuple(resources),
        sid=sid,
        raw_statement=raw,
    )


def _fetch_inline_policy_source(
    policy_id: str,
    policy_type: str,
    principal: PrincipalInfo,
    iam_client,
) -> PolicySource:
    """
    Fetch an inline policy document.

    *policy_id* for inline policies in MatchedStatements is the policy name,
    not an ARN.  We infer the entity from *principal*.
    """
    document: dict = {}
    if policy_type == "User" or (
        principal.principal_type in (PrincipalType.USER, PrincipalType.ASSUMED_ROLE)
    ):
        resp = iam_client.get_user_policy(UserName=principal.name, PolicyName=policy_id)
        document = resp["PolicyDocument"]
    elif policy_type == "Role" or principal.principal_type == PrincipalType.ROLE:
        resp = iam_client.get_role_policy(RoleName=principal.name, PolicyName=policy_id)
        document = resp["PolicyDocument"]

    statements = document.get("Statement", [])
    raw = statements[0] if statements else None
    effect = raw.get("Effect") if raw else None
    actions = _normalize_list(raw.get("Action", [])) if raw else ()
    resources = _normalize_list(raw.get("Resource", [])) if raw else ()
    sid = raw.get("Sid") if raw else None
    return PolicySource(
        policy_id=policy_id,
        policy_type=policy_type,
        effect=effect,
        actions=tuple(actions),
        resources=tuple(resources),
        sid=sid,
        raw_statement=raw,
    )


def _normalize_list(value: str | list) -> list[str]:
    if isinstance(value, str):
        return [value]
    return list(value)
