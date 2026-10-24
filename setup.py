from setuptools import setup, find_packages

setup(
    name="shadowharness",
    version="1.0.0",
    description="In-Flight Behavioral Firewall and Time-Travel Execution Harness for Autonomous AI Agents",
    author="ShadowHarness Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.22.0",
        "pydantic>=2.0.0",
        "websockets>=11.0",
    ],
    entry_points={
        "console_scripts": [
            "shadowharness=shadowharness.cli:main",
        ],
    },
)
