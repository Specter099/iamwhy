"""iamwhy CLI entry point."""

from __future__ import annotations

import sys

import boto3
import botocore.exceptions
import click
from rich.console import Console

from .analyzer import analyze
from .formatters import get_formatter
from .models import DecisionType
from .resolver import resolve_principal
from .simulator import SimulationError, build_context_entries, simulate


@click.command()
@click.argument("principal")
@click.argument("action")
@click.option(
    "--resource",
    default="*",
    show_default=True,
    help="Resource ARN to simulate against.",
)
@click.option(
    "--context",
    multiple=True,
    metavar="KEY=VALUE",
    help="Simulation context entry (repeatable). Example: aws:SourceIp=1.2.3.4",
)
@click.option(
    "--output",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--profile",
    default=None,
    envvar="AWS_PROFILE",
    help="AWS credentials profile name.",
)
@click.option(
    "--region",
    default=None,
    envvar="AWS_DEFAULT_REGION",
    help="AWS region.",
)
def main(
    principal: str,
    action: str,
    resource: str,
    context: tuple[str, ...],
    output: str,
    profile: str | None,
    region: str | None,
) -> None:
    """Explain why an AWS IAM action is denied for a given principal.

    PRINCIPAL can be an IAM ARN, an STS assumed-role session ARN, a username,
    or a role name.  ACTION is an AWS action string such as s3:GetObject.

    Exit code is 0 for allowed, 1 for denied.
    """
    # Diagnostics (errors) go to stderr; verdicts go to stdout.
    err = Console(stderr=True, highlight=False)

    # 1. Build boto3 session
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        iam = session.client("iam")
    except botocore.exceptions.ProfileNotFound as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)

    # 2. Resolve principal
    try:
        principal_info = resolve_principal(principal, iam)
    except ValueError as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)
    except botocore.exceptions.ClientError as exc:
        _handle_client_error(exc, err)
        sys.exit(2)

    # 3. Parse context entries
    try:
        context_entries = build_context_entries(list(context))
    except ValueError as exc:
        err.print(f"[bold red]Error:[/bold red] Invalid --context entry: {exc}")
        sys.exit(2)

    # 4. Simulate
    try:
        sim_result = simulate(
            principal_info.arn, action, resource, context_entries, iam
        )
    except SimulationError as exc:
        err.print(f"[bold red]Simulation error ({exc.error_code}):[/bold red] {exc}")
        if exc.error_code == "AccessDenied":
            err.print(
                "[dim]iamwhy requires iam:SimulatePrincipalPolicy and "
                "iam:GetUser/GetRole permissions.[/dim]"
            )
        sys.exit(2)
    except ValueError as exc:
        err.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(2)

    # 5. Analyze
    fetch = output != "json"  # skip GetPolicyVersion for JSON — reduces API calls
    verdict = analyze(sim_result, principal_info, iam, fetch_statements=fetch)

    # 6. Format and output
    out_console = Console(highlight=False)
    formatter = get_formatter(output, console=out_console)
    formatter.render(verdict)

    # 7. Exit code: 0 = allowed, non-zero = denied
    if verdict.decision != DecisionType.ALLOWED:
        sys.exit(1)


def _handle_client_error(
    exc: botocore.exceptions.ClientError, console: Console
) -> None:
    code = exc.response["Error"]["Code"]
    msg = exc.response["Error"]["Message"]
    if code == "AccessDenied":
        console.print(f"[bold red]Access denied:[/bold red] {msg}")
        console.print(
            "[dim]iamwhy requires iam:SimulatePrincipalPolicy and "
            "iam:GetUser/GetRole permissions.[/dim]"
        )
    elif code == "NoSuchEntity":
        console.print(f"[bold red]Not found:[/bold red] {msg}")
    else:
        console.print(f"[bold red]AWS error ({code}):[/bold red] {msg}")
