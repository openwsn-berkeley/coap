import logging
import testUtils as utils

import time
import threading

from conftest import IPADDRESS1, \
                     RESOURCE, \
                     DUMMYVAL
from coap     import coapDefines as d

#============================ logging ===============================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())
    
#============================ tests ===========================================

def test_GET(logFixture,snoopyDispatcher,twoEndPoints):
    
    (coap1,coap2) = twoEndPoints
    
    # have coap2 do a get
    reply = coap2.GET(
        uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE),
        confirmable = False,
    )
    assert reply==DUMMYVAL
    
