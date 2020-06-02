import logging
import testUtils as utils

import time
import threading

import pytest

from conftest import IPADDRESS1, \
                     RESOURCE, \
                     DUMMYVAL, \
                     OSCORECLIENTCONTEXT
from coap     import coapDefines as d, \
                     coapException as e, \
                     coapOption as o, \
                     coapObjectSecurity as oscore

#============================ logging =========================================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ logging =========================================

#============================ tests ===========================================

def test_METHODNOTALLOWED(logFixture,snoopyDispatcher,twoEndPoints,confirmableFixture):
    
    (coap1,coap2, securityEnabled) = twoEndPoints

    options = []
    if securityEnabled:
        context = oscore.SecurityContext(OSCORECLIENTCONTEXT)

        options = [o.ObjectSecurity(context=context)]
    
    # have coap2 do a post
    with pytest.raises(e.coapRcMethodNotAllowed):
        reply = coap2.POST(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE),
            confirmable = confirmableFixture,
            options=options
        )
