import logging
import testUtils as utils

import time
import threading

import pytest

import binascii

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

def test_UNAUTHORIZED_1(logFixture,snoopyDispatcher,twoEndPoints,confirmableFixture):
    
    (coap1,coap2, securityEnabled) = twoEndPoints

    options = []
    if securityEnabled:
        # have coap2 do a get without including an Object-Security option
        with pytest.raises(e.coapRcUnauthorized):
            reply = coap2.GET(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE),
            confirmable = confirmableFixture,
            options=[]
        )
    else:
        pass

DUMMYMASTERSECRET  = binascii.unhexlify('DEADBEEFDEADBEEFDEADBEEF')
DUMMYSERVERID      = binascii.unhexlify('CAFECAFECAFE')
DUMMYCLIENTID      = binascii.unhexlify('FECAFECAFECA')

def test_UNAUTHORIZED_2(logFixture, snoopyDispatcher, twoEndPoints, confirmableFixture):
    (coap1, coap2, securityEnabled) = twoEndPoints

    options = []
    if securityEnabled:
        # have coap2 do a get with wrong context
        clientContext = oscoap.SecurityContext(masterSecret=DUMMYMASTERSECRET,
                                               senderID=DUMMYSERVERID,
                                               recipientID=DUMMYCLIENTID)

        clientOptions = [o.ObjectSecurity(context=clientContext)]

        with pytest.raises(e.coapRcUnauthorized):
            reply = coap2.GET(
                uri='coap://[{0}]:{1}/{2}/'.format(IPADDRESS1, d.DEFAULT_UDP_PORT, RESOURCE),
                confirmable=confirmableFixture,
                options=clientOptions
            )
    else:
        pass
