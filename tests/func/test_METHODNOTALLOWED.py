import logging
import testUtils as utils

import time
import threading

import pytest

from conftest import IPADDRESS1, \
                     RESOURCE, \
                     DUMMYVAL
from coap     import coapDefines as d, \
                     coapException as e

#============================ logging =========================================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ logging =========================================

#============================ tests ===========================================

def test_NOTFOUND(logFixture,snoopyDispatcher,twoEndPoints,confirmableFixture):
    
    (coap1,coap2) = twoEndPoints
    
    # have coap2 do a get
    with pytest.raises(e.coapRcMethodNotAllowed):
        reply = coap2.POST(
            uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE),
            confirmable = confirmableFixture,
        )
