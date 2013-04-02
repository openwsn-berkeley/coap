import logging
import testUtils as utils

import time
import threading

import pytest

from conftest import IPADDRESS1, \
                     RESOURCE, \
                     DUMMYVAL
from coap     import coapDefines as d, \
                     coapResource, \
                     coapException as e

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

def test_GET(logFixture,snoopyDispatcher,twoEndPoints):
    
    (coap1,coap2) = twoEndPoints
    
    coap1.addResource(buggyResource())
    
    # have coap2 do a get
    with pytest.raises(e.coapRcInternalServerError):
        reply = coap2.GET(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,'buggy'),
            confirmable = True,
        )
    
