import os

from setuptools import setup

# retrieve the version number
from coap import coapVersion

VERSION = '.'.join([str(v) for v in coapVersion.VERSION])

with open('README.md') as f:
    LONG_DESCRIPTION = f.read()

with open('COPYING.txt') as f:
    LICENSE = f.read()

# Create list of required modules for 'install_requires' parameter. Cannot create
# this list with pip.req.parse_requirements() because it requires the pwd module,
# which is Unix only.
# Assumes requirements file contains only module lines and comments.
deplist = []
with open(os.path.join('requirements.txt')) as f:
    for line in f:
        if not line.startswith('#'):
            deplist.append(line)

setup(
    name="openwsn-coap",
    packages=["coap"],
    version=VERSION,
    author="Thomas Watteyne",
    author_email="watteyne@eecs.berkeley.edu",
    description="A CoAP Python library",
    long_description=LONG_DESCRIPTION,
    url="http://www.openwsn.org/",
    keywords=["CoAP", "Internet of Things", "IETF CORE"],
    license=LICENSE,
    install_requires=deplist,
    platforms=['platform-independent'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Topic :: Communications",
        "Topic :: Home Automation",
        "Topic :: Internet",
        # "Topic :: Internet :: Proxy Servers",
        # "Topic :: Internet :: WWW/HTTP :: Browsers",
        # "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
