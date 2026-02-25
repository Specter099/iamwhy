"""Render a Verdict to the terminal (Rich) or as JSON."""
from __future__ import annotations

import dataclasses
import json
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import DecisionType, DenialCause, PolicyBreakdown, Verdict


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class TextFormatter:
    """Renders a Verdict using Rich for human-readable terminal output."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console(highlight=False)

    def render(self, verdict: Verdict) -> None:
        c = self.console

        # Header: principal / action / resource
        c.print(f"[bold]Principal:[/bold] {verdict.principal.arn}")
        c.print(f"[bold]Action:   [/bold] {verdict.action}")
        c.print(f"[bold]Resource: [/bold] {verdict.resource}")
        c.print()

        # Verdict line
        label, style = _verdict_label(verdict.decision)
        verdict_text = Text()
        verdict_text.append("Verdict: ", style="bold")
        verdict_text.append(label, style=style)
        c.print(verdict_text)
        c.print()

        # Summary
        c.print(f"[bold]Reason:[/bold] {verdict.summary}")

        # Blocking policies with statement details
        if verdict.blocking_policies:
            c.print()
            for bp in verdict.blocking_policies:
                _render_policy_breakdown(c, bp)

        # Decision breakdown table
        if verdict.all_breakdown:
            c.print()
            table = Table(
                title="Decision breakdown",
                show_header=True,
                header_style="bold",
                box=None,
                padding=(0, 2),
            )
            table.add_column("Policy", style="dim")
            table.add_column("Decision")
            for b in verdict.all_breakdown:
                dec_style = _decision_style(b.decision)
                table.add_row(b.policy_id, Text(b.decision, style=dec_style))
            c.print(table)

        # Missing context
        c.print()
        if verdict.missing_context:
            keys = ", ".join(verdict.missing_context)
            c.print(f"[bold]Missing context:[/bold] {keys}")
        else:
            c.print("[bold]Missing context:[/bold] [dim](none)[/dim]")

        # Extra flags
        if verdict.orgs_blocked:
            c.print("[yellow]Note:[/yellow] An SCP denies this action at the organization level.")
        if verdict.boundary_blocked:
            c.print(
                "[yellow]Note:[/yellow] The principal's permissions boundary does not "
                "allow this action."
            )


class JsonFormatter:
    """Renders a Verdict as a JSON document to stdout."""

    def __init__(self, indent: int = 2) -> None:
        self.indent = indent

    def render(self, verdict: Verdict) -> None:
        data = _verdict_to_dict(verdict)
        print(json.dumps(data, indent=self.indent, default=str))


def get_formatter(
    output: str, console: Optional[Console] = None
) -> TextFormatter | JsonFormatter:
    """Factory: ``'text'`` → TextFormatter, ``'json'`` → JsonFormatter."""
    if output == "json":
        return JsonFormatter()
    return TextFormatter(console=console)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _verdict_label(decision: DecisionType) -> tuple[str, str]:
    if decision == DecisionType.ALLOWED:
        return "ALLOWED", "bold green"
    if decision == DecisionType.EXPLICIT_DENY:
        return "DENIED (explicit deny)", "bold red"
    return "DENIED (implicit deny)", "bold yellow"


def _decision_style(decision: str) -> str:
    if decision == "allowed":
        return "green"
    if decision == "explicitDeny":
        return "red"
    return "yellow"


def _render_policy_breakdown(console: Console, bp: PolicyBreakdown) -> None:
    lines: list[str] = []

    if bp.source is not None:
        src = bp.source
        if src.sid:
            lines.append(f"Statement: Sid={src.sid}")
        if src.effect:
            lines.append(f"  Effect:  {src.effect}")
        if src.actions:
            actions_str = ", ".join(src.actions)
            lines.append(f"  Action:  {actions_str}")
        if src.resources:
            resources_str = ", ".join(src.resources)
            lines.append(f"  Resource: {resources_str}")
        if src.raw_statement is None:
            lines.append(
                "  [dim]statement text unavailable — "
                "insufficient iam:GetPolicy permissions[/dim]"
            )
    else:
        lines.append("[dim](statement details unavailable)[/dim]")

    body = "\n".join(lines) if lines else "[dim](no details)[/dim]"
    policy_type = bp.source.policy_type if bp.source else "unknown"
    console.print(
        Panel(
            body,
            title=f"[bold]{bp.policy_id}[/bold] [dim]({policy_type})[/dim]",
            expand=False,
        )
    )


def _verdict_to_dict(verdict: Verdict) -> dict:
    return {
        "principal": verdict.principal.arn,
        "principal_type": verdict.principal.principal_type.value,
        "action": verdict.action,
        "resource": verdict.resource,
        "decision": verdict.decision.value,
        "cause": verdict.cause.value,
        "summary": verdict.summary,
        "orgs_blocked": verdict.orgs_blocked,
        "boundary_blocked": verdict.boundary_blocked,
        "missing_context": list(verdict.missing_context),
        "blocking_policies": [
            {
                "policy_id": bp.policy_id,
                "decision": bp.decision,
                "statement": bp.source.raw_statement if bp.source else None,
            }
            for bp in verdict.blocking_policies
        ],
        "all_breakdown": [
            {"policy_id": b.policy_id, "decision": b.decision}
            for b in verdict.all_breakdown
        ],
    }
