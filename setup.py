from setuptools import setup, find_packages

setup(
    name="vulpimancer",
    version="1.0.0",
    description="Async Recon Engine — Authorised Security Assessments Only",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "aiohttp>=3.9.0",
        "aiosqlite>=0.20.0",
        "aiodns>=3.1.1",
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "vulpimancer=vulpimancer.core:main",
        ]
    },
)
