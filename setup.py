#!/usr/bin/env python3
"""Backward-compatible setup.py for NodiGuard Community Edition."""
from setuptools import setup, find_packages

setup(
    name="nodiguard",
    version="0.1.0",
    packages=find_packages(include=["nodiguard*"]),
    install_requires=[
        "requests>=2.28.0",
        "psutil>=5.9.0",
    ],
    entry_points={
        "console_scripts": [
            "nodiguard = nodiguard.cli:main",
        ],
    },
)
