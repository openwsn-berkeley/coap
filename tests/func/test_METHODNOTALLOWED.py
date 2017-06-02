import logging
import testUtils as utils

import time
import threading

import pytest

from conftest import IPADDRESS1, \
                     RESOURCE, \
                     DUMMYVAL, \
                     OSCOAPMASTERSECRET, \
                     OSCOAPSERVERID, \
                     OSCOAPCLIENTID
from coap     import coapDefines as d, \
                     coapException as e, \
                     coapOption as o, \
                     coapObjectSecurity as oscoap

#============================ logging =========================================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ logging =========================================

#============================ tests ===========================================

def test_METHODNOTALLOWED(logFixture,snoopyDispatcher,twoEndPoints,confirmableFixture):
    
    (coap1,coap2, securityEnabled) = twoEndPoints

    options = []
    if securityEnabled:
        context = oscoap.SecurityContext(masterSecret   = OSCOAPMASTERSECRET,
                                         senderID       = OSCOAPSERVERID,
                                         recipientID    = OSCOAPCLIENTID)

        options = [o.ObjectSecurity(context=context)]
    
    # have coap2 do a post
    with pytest.raises(e.coapRcMethodNotAllowed):
        reply = coap2.POST(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE),
            confirmable = confirmableFixture,
            options=options
        )
