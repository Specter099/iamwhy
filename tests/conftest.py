"""Shared pytest fixtures for iamwhy tests."""
import os
import pytest
import boto3

# moto is imported lazily inside fixtures so the import error surface is clear.


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    """Prevent accidental real AWS calls by setting fake credentials."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def moto_iam():
    """Yield a real boto3 IAM client inside a moto mock_aws context."""
    from moto import mock_aws

    with mock_aws():
        yield boto3.client("iam", region_name="us-east-1")


@pytest.fixture
def sample_user_arn(moto_iam):
    moto_iam.create_user(UserName="alice")
    user = moto_iam.get_user(UserName="alice")["User"]
    return user["Arn"]


@pytest.fixture
def sample_role_arn(moto_iam):
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    moto_iam.create_role(RoleName="MyRole", AssumeRolePolicyDocument=trust)
    role = moto_iam.get_role(RoleName="MyRole")["Role"]
    return role["Arn"]
