"""Resolve an IAM principal string to a PrincipalInfo.

Also enumerates attached policies.
"""

from __future__ import annotations

import re

from botocore.exceptions import ClientError

from .models import PrincipalInfo, PrincipalType

# arn:aws:iam::123456789012:user/alice
# arn:aws:iam::123456789012:role/MyRole
# arn:aws:sts::123456789012:assumed-role/MyRole/session-name
_ARN_RE = re.compile(
    r"^arn:aws(?:-cn|-us-gov)?:(?P<service>iam|sts)::"
    r"(?P<account>\d{12}):(?P<resource_type>[^/]+)/(?P<resource>.+)$"
)


def resolve_principal(raw_input: str, iam_client) -> PrincipalInfo:
    """
    Normalize *raw_input* to a canonical IAM ARN wrapped in a PrincipalInfo.

    Accepts:
    - IAM user ARN     arn:aws:iam::ACCOUNT:user/NAME
    - IAM role ARN     arn:aws:iam::ACCOUNT:role/NAME
    - STS session ARN  arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION
    - Bare username    alice
    - Bare role name   MyRole

    Raises:
        ValueError: input cannot be resolved to a known IAM entity.
        botocore.exceptions.ClientError: AWS permission error.
    """
    m = _ARN_RE.match(raw_input)
    if m:
        return _resolve_arn(m, raw_input, iam_client)
    return _resolve_bare_name(raw_input, iam_client)


def enumerate_policy_ids(principal: PrincipalInfo, iam_client) -> list[str]:
    """
    Return a flat list of policy identifiers attached to *principal*.

    Managed policies are returned as ARNs; inline policies as their names
    (prefixed with ``inline:<entity>/<name>`` for disambiguation).

    Users: attached managed + inline + group-attached managed + group inline.
    Roles: attached managed + inline.
    """
    if principal.principal_type in (PrincipalType.USER, PrincipalType.ASSUMED_ROLE):
        return _enumerate_user_policies(principal.name, iam_client)
    return _enumerate_role_policies(principal.name, iam_client)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_arn(m: re.Match, raw_input: str, iam_client) -> PrincipalInfo:
    service = m.group("service")
    account = m.group("account")
    resource_type = m.group("resource_type")
    resource = m.group("resource")

    if service == "iam" and resource_type == "user":
        return _fetch_user_info(resource, account, raw_input, iam_client)

    if service == "iam" and resource_type == "role":
        return _fetch_role_info(resource, account, raw_input, iam_client)

    if service == "sts" and resource_type == "assumed-role":
        # resource = "RoleName/SessionName"
        parts = resource.split("/", 1)
        role_name = parts[0]
        session_name = parts[1] if len(parts) > 1 else None
        info = _fetch_role_info(role_name, account, raw_input, iam_client)
        # Overlay the session name and correct principal type
        return PrincipalInfo(
            arn=info.arn,
            principal_type=PrincipalType.ASSUMED_ROLE,
            account_id=info.account_id,
            name=info.name,
            session_name=session_name,
            raw_input=raw_input,
        )

    raise ValueError(
        f"Unsupported ARN format: {raw_input!r}. "
        "Expected iam:user/*, iam:role/*, or sts:assumed-role/*."
    )


def _resolve_bare_name(name: str, iam_client) -> PrincipalInfo:
    """Try get_user then get_role; raise ValueError if neither exists."""
    try:
        resp = iam_client.get_user(UserName=name)
        user = resp["User"]
        account = _account_from_arn(user["Arn"])
        return PrincipalInfo(
            arn=user["Arn"],
            principal_type=PrincipalType.USER,
            account_id=account,
            name=name,
            session_name=None,
            raw_input=name,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        resp = iam_client.get_role(RoleName=name)
        role = resp["Role"]
        account = _account_from_arn(role["Arn"])
        return PrincipalInfo(
            arn=role["Arn"],
            principal_type=PrincipalType.ROLE,
            account_id=account,
            name=name,
            session_name=None,
            raw_input=name,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    raise ValueError(
        f"No IAM user or role named {name!r} found. "
        "Provide a full ARN or check the name spelling."
    )


def _fetch_user_info(
    username: str, account_id: str, raw_input: str, iam_client
) -> PrincipalInfo:
    resp = iam_client.get_user(UserName=username)
    user = resp["User"]
    return PrincipalInfo(
        arn=user["Arn"],
        principal_type=PrincipalType.USER,
        account_id=account_id,
        name=username,
        session_name=None,
        raw_input=raw_input,
    )


def _fetch_role_info(
    role_name: str, account_id: str, raw_input: str, iam_client
) -> PrincipalInfo:
    resp = iam_client.get_role(RoleName=role_name)
    role = resp["Role"]
    return PrincipalInfo(
        arn=role["Arn"],
        principal_type=PrincipalType.ROLE,
        account_id=account_id,
        name=role_name,
        session_name=None,
        raw_input=raw_input,
    )


def _account_from_arn(arn: str) -> str:
    """Extract the 12-digit account ID from an ARN."""
    parts = arn.split(":")
    return parts[4] if len(parts) >= 5 else ""


# ---------------------------------------------------------------------------
# Policy enumeration helpers
# ---------------------------------------------------------------------------


def _enumerate_user_policies(username: str, iam_client) -> list[str]:
    policy_ids: list[str] = []

    # Managed policies attached directly to the user
    paginator = iam_client.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=username):
        for p in page["AttachedPolicies"]:
            policy_ids.append(p["PolicyArn"])

    # Inline policies on the user
    paginator = iam_client.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=username):
        for name in page["PolicyNames"]:
            policy_ids.append(f"inline:user/{username}/{name}")

    # Group memberships
    try:
        paginator = iam_client.get_paginator("list_groups_for_user")
        for page in paginator.paginate(UserName=username):
            for group in page["Groups"]:
                gname = group["GroupName"]
                # Managed policies on the group
                gp = iam_client.get_paginator("list_attached_group_policies")
                for gpage in gp.paginate(GroupName=gname):
                    for p in gpage["AttachedPolicies"]:
                        if p["PolicyArn"] not in policy_ids:
                            policy_ids.append(p["PolicyArn"])
                # Inline policies on the group
                gip = iam_client.get_paginator("list_group_policies")
                for gpage in gip.paginate(GroupName=gname):
                    for iname in gpage["PolicyNames"]:
                        policy_ids.append(f"inline:group/{gname}/{iname}")
    except ClientError:
        pass

    return policy_ids


def _enumerate_role_policies(role_name: str, iam_client) -> list[str]:
    policy_ids: list[str] = []

    paginator = iam_client.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for p in page["AttachedPolicies"]:
            policy_ids.append(p["PolicyArn"])

    paginator = iam_client.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for name in page["PolicyNames"]:
            policy_ids.append(f"inline:role/{role_name}/{name}")

    return policy_ids
