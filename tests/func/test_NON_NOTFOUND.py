import logging
import testUtils as utils

import time
import threading

import pytest

from conftest import IPADDRESS1, \
                     DUMMYVAL
from coap     import coapDefines as d, \
                     coapException as e

#============================ logging =========================================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ logging =========================================

RESOURCE_INVALID = 'invalid'

#============================ tests ===========================================

def test_GET(logFixture,snoopyDispatcher,twoEndPoints):
    
    (coap1,coap2) = twoEndPoints
    
    # have coap2 do a get
    with pytest.raises(e.coapRcNotFound):
        reply = coap2.GET(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE_INVALID),
            confirmable = False,
        )
    
