# -*- coding: utf-8 -*-

import setuptools

from W13SCAN import VERSION, REPOSITORY

with open('README.md', 'r') as f:
    long_description = f.read()

with open('requirements.txt', 'r') as f:
    install_requires = f.readlines()
    install_requires = [i.strip() for i in install_requires]

setuptools.setup(
    name='w13scan',
    version=VERSION,
    author='boy-hack',
    author_email='master@hacking8.com',
    description='Passive Web Security Scanner',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords='scanner,w13scan',
    platforms=['any'],
    url=REPOSITORY,
    python_requires='>=3.4',
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    include_package_data=True,
    classifiers=(
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)"
    ),
    entry_points={
        'console_scripts': [
            'w13scan = W13SCAN.cli:main'
        ]
    }
)
