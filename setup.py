#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='quart',
    version='1.0.0',
    author='Victor Leconte',
    author_email='v.leconte@criteo.com',
    description='Your project description',
    data_files=(
        ('/etc/', ('etc/quart_config.conf',)),
    ),
    packages=find_packages(),
    install_requires=[
        'confiture',
        'requests',
        'jira',
    ],
    entry_points={
        'console_scripts': [
            'quart=quart.cli:main',
        ],
    },
)
