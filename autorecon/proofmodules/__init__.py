"""Pluggable proof-of-exploit modules with shared HTTP guardrails."""

from autorecon.proofmodules.base import ProofModule
from autorecon.proofmodules.commandinjection import CommandInjection
from autorecon.proofmodules.lfi import FileInclusion
from autorecon.proofmodules.sqli import SQLInjection
from autorecon.proofmodules.ssrf import SSRF
from autorecon.proofmodules.ssti import TemplateExpression
from autorecon.proofmodules.xxe import XXE


def all_modules():
    """Every registered module, in run order. SSTI stays first for compatibility."""
    return [TemplateExpression(), CommandInjection(), SQLInjection(), FileInclusion(), SSRF(), XXE()]


def select_modules(names=None):
    """Resolve module names (or None for all) to module instances."""
    available = {module.name: module for module in all_modules()}
    if names is None:
        return all_modules()
    selected = []
    for name in names:
        if name not in available:
            raise ValueError('Unknown proof module: ' + str(name) + '. Choose from: ' + ', '.join(available))
        if available[name] not in selected:
            selected.append(available[name])
    return selected
