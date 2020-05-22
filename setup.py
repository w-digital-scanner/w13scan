"""Setup file for w13scan."""
from setuptools import setup, find_packages

with open("README.md", "r") as readme_file:
    long_description = readme_file.read()

with open("requirements.txt", "r") as requirements_file:
    install_requires = requirements_file.readlines()
    install_requires = [i.strip() for i in install_requires]

setup(
    name="w13scan",
    version="2.0.2",
    author="boy-hack",
    author_email="master@hacking8.com",
    description="Passive Web Security Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="scanner, w13scan",
    platforms=["any"],
    url="https://github.com/w-digital-scanner/w13scan",
    python_requires=">=3.4",
    packages=find_packages(),
    install_requires=install_requires,
    include_package_data=True,
    classifiers=(
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    ),
    entry_points={"console_scripts": ["w13scan = W13SCAN.cli:main"]},
)
