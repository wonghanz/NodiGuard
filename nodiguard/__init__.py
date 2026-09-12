"""
NodiGuard Community Edition (开源社区版)
Zero-Trust Local AI Security Gateway, Pre-Flight DLP Sentinel & System Memory Optimizer.
"""

__version__ = "0.1.0"
__author__ = "NodiGuard Open Source Team"
__license__ = "Apache-2.0"

from .dlp import NodiGuardDLP, DLPScanResult
from .anonymizer import TokenAnonymizer
from .optimizer import SystemOptimizer
from .proxy import NodiProxy

__all__ = [
    "NodiGuardDLP",
    "DLPScanResult",
    "TokenAnonymizer",
    "SystemOptimizer",
    "NodiProxy",
]
