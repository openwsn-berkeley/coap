from distutils.core import setup

setup(
    name           = "coap",
    packages       = ["coap"],
    version        = "1.0.0",
    author         = "Thomas Watteyne",
    author_email   = "watteyne@eecs.berkeley.edu",
    description    = "A CoAP Python library",
    url            = "http://www.openwsn.org/",
    keywords       = ["CoAP","Internet of Things","IETF CORE"],
    classifiers    = [
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Topic :: Communications",
        "Topic :: Home Automation",
        "Topic :: Internet",
        #"Topic :: Internet :: Proxy Servers",
        #"Topic :: Internet :: WWW/HTTP :: Browsers",
        #"Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    long_description = """\
CoAP Python library
-------------------

This package implements the Constrained Application Protocol (CoAP)
developed by the IETF CORE working group.

This package aims at implementing:
http://tools.ietf.org/html/draft-ietf-core-coap-13

In particular, it implements:
- a CoAP client
- a CoAP server with an arbitrary number of resources

It does NOT currently implement:
- CoAP proxying
- CoAP caching
- HTTP-to-CoAP or CoAP-to-HTTP cross-proxying

This package contains Doxygen-based HTML documentation.

More documentation at http://www.openwsn.org/.
Report bugs at https://openwsn.atlassian.net/browse/COAP.

This package is part of Berkeley's OpenWSN project,
http://www.openwsn.org/.
"""
)