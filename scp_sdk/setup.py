"""
Setup script for the SCP SDK.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="scp-sdk",
    version="1.0.0",
    author="SecureContext Protocol Team",
    author_email="team@securecontext.dev",
    description="Python SDK for the SecureContext Protocol Authentication Proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/securecontext/scp-sdk",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "langchain": ["langchain>=0.1.0"],
        "crewai": ["crewai>=0.1.0"],
        "autogen": ["pyautogen>=0.1.0"],
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "all": [
            "langchain>=0.1.0",
            "crewai>=0.1.0", 
            "pyautogen>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "scp-verify=scp_sdk.cli:verify_tokens",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/securecontext/scp-sdk/issues",
        "Source": "https://github.com/securecontext/scp-sdk",
        "Documentation": "https://docs.securecontext.dev/sdk",
    },
)