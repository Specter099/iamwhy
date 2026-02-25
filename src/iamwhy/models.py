"""Pure data models for iamwhy. No I/O, no AWS calls."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PrincipalType(Enum):
    USER = "user"
    ROLE = "role"
    ASSUMED_ROLE = "assumed-role"


class DecisionType(Enum):
    ALLOWED = "allowed"
    EXPLICIT_DENY = "explicitDeny"
    IMPLICIT_DENY = "implicitDeny"


class DenialCause(Enum):
    EXPLICIT_DENY = "explicit_deny"
    IMPLICIT_DENY = "implicit_deny"
    SCP_BLOCK = "scp_block"
    PERMISSIONS_BOUNDARY = "permissions_boundary"
    MISSING_CONTEXT = "missing_context"
    COMBINED = "combined"


@dataclass(frozen=True)
class PrincipalInfo:
    """Resolved IAM principal with a canonical ARN."""

    arn: str
    principal_type: PrincipalType
    account_id: str
    name: str
    session_name: Optional[str]
    raw_input: str


@dataclass(frozen=True)
class PolicySource:
    """A matched policy statement retrieved from GetPolicyVersion / GetXxxPolicy."""

    policy_id: str
    policy_type: str
    effect: Optional[str]
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    sid: Optional[str]
    raw_statement: Optional[dict]


@dataclass(frozen=True)
class SimulationResult:
    """Direct mapping of a single EvaluationResult from SimulatePrincipalPolicy."""

    principal_arn: str
    action: str
    resource: str
    eval_decision: str
    matched_statements: tuple[dict, ...]
    eval_decision_details: dict[str, str]
    missing_context_values: tuple[str, ...]
    orgs_allowed: Optional[bool]
    boundary_allowed: Optional[bool]


@dataclass(frozen=True)
class PolicyBreakdown:
    """Per-policy decision entry in a Verdict."""

    policy_id: str
    decision: str
    source: Optional[PolicySource] = field(default=None)


@dataclass(frozen=True)
class Verdict:
    """Human-readable conclusion produced by the analyzer."""

    principal: PrincipalInfo
    action: str
    resource: str
    decision: DecisionType
    cause: DenialCause
    summary: str
    blocking_policies: tuple[PolicyBreakdown, ...]
    all_breakdown: tuple[PolicyBreakdown, ...]
    missing_context: tuple[str, ...]
    orgs_blocked: bool
    boundary_blocked: bool
