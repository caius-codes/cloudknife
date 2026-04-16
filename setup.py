#!/usr/bin/env python3
"""
CloudKnife setup configuration.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from version.py
version = {}
with open("src/version.py") as f:
    exec(f.read(), version)

# Read long description from README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="cloudknife",
    version=version["__version__"],
    description="Multi-cloud penetration testing and enumeration tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="CloudKnife Contributors",
    author_email="",
    url="https://github.com/caius-code/cloudknife",  # Update with actual URL
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cloudknife=src.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="cloud security pentest aws gcp azure enumeration",
    project_urls={
        "Bug Reports": "https://github.com/caius-code/cloudknife/issues",
        "Source": "https://github.com/caius-code/cloudknife",
    },
)
