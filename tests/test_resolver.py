"""Tests for iamwhy.resolver."""

import pytest

from iamwhy.models import PrincipalType
from iamwhy.resolver import enumerate_policy_ids, resolve_principal

ACCOUNT = "123456789012"

_TRUST = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
)
_POLICY_DOC = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}'
)


# ---------------------------------------------------------------------------
# ARN parsing — unit-level (no moto needed)
# ---------------------------------------------------------------------------


def test_resolve_user_arn(moto_iam):
    moto_iam.create_user(UserName="alice")
    arn = moto_iam.get_user(UserName="alice")["User"]["Arn"]
    info = resolve_principal(arn, moto_iam)
    assert info.principal_type == PrincipalType.USER
    assert info.name == "alice"
    assert info.session_name is None
    assert info.arn == arn


def test_resolve_role_arn(moto_iam):
    moto_iam.create_role(RoleName="MyRole", AssumeRolePolicyDocument=_TRUST)
    arn = moto_iam.get_role(RoleName="MyRole")["Role"]["Arn"]
    info = resolve_principal(arn, moto_iam)
    assert info.principal_type == PrincipalType.ROLE
    assert info.name == "MyRole"
    assert info.session_name is None


def test_resolve_assumed_role_arn(moto_iam):
    moto_iam.create_role(RoleName="MyRole", AssumeRolePolicyDocument=_TRUST)
    role_arn = moto_iam.get_role(RoleName="MyRole")["Role"]["Arn"]

    sts_arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/MyRole/my-session"
    info = resolve_principal(sts_arn, moto_iam)
    assert info.principal_type == PrincipalType.ASSUMED_ROLE
    assert info.session_name == "my-session"
    # The canonical ARN must be the IAM role ARN, not the STS session ARN
    assert info.arn == role_arn
    assert "assumed-role" not in info.arn


def test_resolve_bare_username(moto_iam):
    moto_iam.create_user(UserName="bob")
    info = resolve_principal("bob", moto_iam)
    assert info.principal_type == PrincipalType.USER
    assert info.name == "bob"


def test_resolve_bare_role_name(moto_iam):
    moto_iam.create_role(RoleName="DevRole", AssumeRolePolicyDocument=_TRUST)
    info = resolve_principal("DevRole", moto_iam)
    assert info.principal_type == PrincipalType.ROLE
    assert info.name == "DevRole"


def test_resolve_bare_name_not_found_raises(moto_iam):
    with pytest.raises(ValueError, match="No IAM user or role"):
        resolve_principal("nonexistent-principal", moto_iam)


def test_resolve_unsupported_arn_raises(moto_iam):
    bad_arn = f"arn:aws:iam::{ACCOUNT}:group/MyGroup"
    with pytest.raises(ValueError, match="Unsupported ARN"):
        resolve_principal(bad_arn, moto_iam)


# ---------------------------------------------------------------------------
# enumerate_policy_ids
# ---------------------------------------------------------------------------


def test_enumerate_user_managed_policy(moto_iam):
    moto_iam.create_user(UserName="carol")
    pol = moto_iam.create_policy(PolicyName="MyPolicy", PolicyDocument=_POLICY_DOC)
    pol_arn = pol["Policy"]["Arn"]
    moto_iam.attach_user_policy(UserName="carol", PolicyArn=pol_arn)

    from iamwhy.models import PrincipalInfo, PrincipalType

    info = PrincipalInfo(
        arn=moto_iam.get_user(UserName="carol")["User"]["Arn"],
        principal_type=PrincipalType.USER,
        account_id=ACCOUNT,
        name="carol",
        session_name=None,
        raw_input="carol",
    )
    ids = enumerate_policy_ids(info, moto_iam)
    assert pol_arn in ids


def test_enumerate_user_inline_policy(moto_iam):
    moto_iam.create_user(UserName="dave")
    moto_iam.put_user_policy(
        UserName="dave", PolicyName="InlinePolicy", PolicyDocument=_POLICY_DOC
    )
    from iamwhy.models import PrincipalInfo, PrincipalType

    info = PrincipalInfo(
        arn=moto_iam.get_user(UserName="dave")["User"]["Arn"],
        principal_type=PrincipalType.USER,
        account_id=ACCOUNT,
        name="dave",
        session_name=None,
        raw_input="dave",
    )
    ids = enumerate_policy_ids(info, moto_iam)
    assert any("InlinePolicy" in i for i in ids)


def test_enumerate_user_group_policy(moto_iam):
    moto_iam.create_user(UserName="eve")
    moto_iam.create_group(GroupName="Devs")
    moto_iam.add_user_to_group(UserName="eve", GroupName="Devs")
    pol = moto_iam.create_policy(PolicyName="GroupPolicy", PolicyDocument=_POLICY_DOC)
    pol_arn = pol["Policy"]["Arn"]
    moto_iam.attach_group_policy(GroupName="Devs", PolicyArn=pol_arn)

    from iamwhy.models import PrincipalInfo, PrincipalType

    info = PrincipalInfo(
        arn=moto_iam.get_user(UserName="eve")["User"]["Arn"],
        principal_type=PrincipalType.USER,
        account_id=ACCOUNT,
        name="eve",
        session_name=None,
        raw_input="eve",
    )
    ids = enumerate_policy_ids(info, moto_iam)
    assert pol_arn in ids


def test_enumerate_role_managed_policy(moto_iam):
    moto_iam.create_role(RoleName="R1", AssumeRolePolicyDocument=_TRUST)
    pol = moto_iam.create_policy(PolicyName="RolePolicy", PolicyDocument=_POLICY_DOC)
    pol_arn = pol["Policy"]["Arn"]
    moto_iam.attach_role_policy(RoleName="R1", PolicyArn=pol_arn)

    from iamwhy.models import PrincipalInfo, PrincipalType

    info = PrincipalInfo(
        arn=moto_iam.get_role(RoleName="R1")["Role"]["Arn"],
        principal_type=PrincipalType.ROLE,
        account_id=ACCOUNT,
        name="R1",
        session_name=None,
        raw_input="R1",
    )
    ids = enumerate_policy_ids(info, moto_iam)
    assert pol_arn in ids


def test_enumerate_role_inline_policy(moto_iam):
    moto_iam.create_role(RoleName="R2", AssumeRolePolicyDocument=_TRUST)
    moto_iam.put_role_policy(
        RoleName="R2", PolicyName="RoleInline", PolicyDocument=_POLICY_DOC
    )
    from iamwhy.models import PrincipalInfo, PrincipalType

    info = PrincipalInfo(
        arn=moto_iam.get_role(RoleName="R2")["Role"]["Arn"],
        principal_type=PrincipalType.ROLE,
        account_id=ACCOUNT,
        name="R2",
        session_name=None,
        raw_input="R2",
    )
    ids = enumerate_policy_ids(info, moto_iam)
    assert any("RoleInline" in i for i in ids)
