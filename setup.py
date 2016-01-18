#!/usr/bin/env python

from distutils.core import setup
import sys

if sys.version_info[0] != 3:
    print('Only Python 3 is supported')
    sys.exit(1)

setup(name='srpc',
      version='0.2.1',
      description='Simple Secure RPC',
      author='Lucas Ryan',
      author_email='badmofo@gmail.com',
      url='http://github.com/badmofo/srpc',
      packages=['srpc'],
      install_requires=[
              'PyNaCl>=0.3.0',
          ],
      )
