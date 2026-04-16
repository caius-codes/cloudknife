"""
MFA Bypass Auditing Module for Azure.

Based on FindMeAccess by Ryan McFarland (MIT License)
https://github.com/absolomb/FindMeAccess

Adapted and integrated into CloudKnife with additional features:
- Automatic session creation for successful bypasses
- Integration with CloudKnife session manager
- Enhanced reporting and user experience
- Automatic triggering on MFA authentication failures

This module tests various combinations of Azure Client IDs and Resources
using ROPC (Resource Owner Password Credentials) flow to identify
configurations that don't enforce MFA.
"""

from .audit import audit_mfa_gaps, test_ropc_combination, display_bypass_results
from .session_creator import create_bypass_sessions
from .client_ids import CLIENT_IDS
from .resources import RESOURCES
from .user_agents import USER_AGENTS

__all__ = [
    "audit_mfa_gaps",
    "test_ropc_combination",
    "display_bypass_results",
    "create_bypass_sessions",
    "CLIENT_IDS",
    "RESOURCES",
    "USER_AGENTS",
]
