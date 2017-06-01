import logging
import testUtils as utils

import time
import threading

import pytest

import binascii

from conftest import IPADDRESS1, \
                     RESOURCE, \
                     DUMMYVAL
from coap     import coapDefines as d, \
                     coapResource, \
                     coapException as e, \
                     coapOption as o, \
                     coapObjectSecurity as oscoap

#============================ logging =========================================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ buggy ===========================================

class buggyResource(coapResource.coapResource):
    
    def __init__(self):
        # initialize parent class
        coapResource.coapResource.__init__(
            self,
            path = 'buggy',
        )
    
    #======================== parent methods ==================================
    
    def GET(self,options=[]):
        log.debug('buggyResource GET')
        
        # raise some exception
        raise ValueError()

#============================ tests ===========================================

DUMMYMASTERSECRET  = binascii.unhexlify('DEADBEEFDEADBEEFDEADBEEF')
DUMMYSERVERID      = binascii.unhexlify('CAFECAFECAFE')
DUMMYCLIENTID      = binascii.unhexlify('FECAFECAFECA')

def test_GET(logFixture,snoopyDispatcher,twoEndPoints):
    
    (coap1,coap2,securityEnabled) = twoEndPoints

    clientOptions = []
    buggyRes = buggyResource()
    if securityEnabled:
        clientContext = oscoap.SecurityContext(masterSecret=DUMMYMASTERSECRET,
                                         senderID=DUMMYSERVERID,
                                         recipientID=DUMMYCLIENTID)

        clientOptions = [o.ObjectSecurity(context=clientContext)]

        serverContext = oscoap.SecurityContext(masterSecret=DUMMYMASTERSECRET,
                                               senderID=DUMMYCLIENTID,
                                               recipientID=DUMMYSERVERID)

        buggyRes.addSecurityBinding((serverContext, d.METHOD_ALL))


    coap1.addResource(buggyRes)
    
    # have coap2 do a get
    with pytest.raises(e.coapRcInternalServerError):
        reply = coap2.GET(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,'buggy'),
            confirmable = True,
            options=clientOptions
        )
    
