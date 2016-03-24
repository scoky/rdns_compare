#!/usr/bin/env python
"""distutils configuration: python setup.py install"""

__author__ = 'kyle.schomp@gmail.com (Kyle Schomp)'

import os
from distutils.core import setup

version = '0.1.0'
kwargs = {
    'name' : 'rdns_compare',
    'version' : version,
    'description' : 'Resolver performance comparison',
    'long_description' : \
    """rdns_compare is a tool for comparing performance of DNS recursive resolvers.""",
    'author' : 'Kyle Schomp',
    'author_email' : 'kyle.schomp@gmail.com',
    'license' : 'MIT',
    'url' : '',
    'packages' : ['rdns_compare_lib', 'thirdparty_lib', 'thirdparty_lib/dns'],
    'download_url' : '',
    'classifiers' : [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: All",
        "Intended Audience :: System Administrators",
        "License :: Freeware",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Topic :: Internet :: Name Service (DNS)",
        ],
    'requires' : [],
    'provides' : ['rdns_compare_lib']
    }

setup(**kwargs)
