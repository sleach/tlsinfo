#!/usr/bin/env python
import re

from setuptools import setup

required = []
with open("requirements.txt") as f:
    required = f.read().splitlines()

version = "0.1.0"

setup_options = dict(
    name="tlsinfo",
    version=version,
    description="tlsinfo",
    url="https://github.com/sleach/tlsinfo",
    author="Sean Leach",
    packages=["tlsinfo"],
    install_requires=required,
    entry_points={
        "console_scripts": [
            "tlsinfo=main",
        ],
    },
)

setup(**setup_options)
