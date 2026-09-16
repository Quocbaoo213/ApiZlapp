#!/usr/bin/env python3
from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="zalo-sdk",
    version="1.0.0",
    description="Python SDK for Zalo Mobile App (TCP Socket Gateway + HTTP/2 REST APIs)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Zalo SDK Team",
    packages=find_packages(include=["core", "core.*"]),
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0.0",
        "pycryptodome>=3.19.0",
        "requests>=2.31.0",
        "urllib3>=2.0.0"
    ],
    entry_points={
        "console_scripts": [
            "zalo-login=core.login.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Communications :: Chat",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
)
