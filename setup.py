import os
from setuptools import find_packages, setup
from setuptools.command.install import install
cur_dir = os.path.dirname(__file__)

with open(f"{cur_dir}/requirements.txt") as f:
    required_packages = f.read().splitlines()

setup(
    name="fortiedr",
    version="3.0",
    description="Open-source python package intended to help on interacting with FortiEDR API.",
    author="Rafael Foster",
    author_email="fosterr@fortinet.com",
    project_urls={
        "GitHub": "https://github.com/rafaelfoster/fortiedr",
    },
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=required_packages,
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Development Status :: 5 - Production/Stable",
    ]
)

