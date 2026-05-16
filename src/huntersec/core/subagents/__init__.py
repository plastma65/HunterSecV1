"""Specialised sub-agents used by high-level solvers.

Each sub-agent owns a narrow responsibility (recon, web, service enum) and
returns a structured ``TypedDict`` summary that downstream agents consume.
"""

from __future__ import annotations

from huntersec.core.subagents.recon_agent import ReconAgent, ReconSummary
from huntersec.core.subagents.service_agent import ServiceAgent, ServiceFindings
from huntersec.core.subagents.web_agent import WebAgent, WebFindings

__all__ = [
    "ReconAgent",
    "ReconSummary",
    "ServiceAgent",
    "ServiceFindings",
    "WebAgent",
    "WebFindings",
]
