import logging
import testUtils as utils

from coap import coap

#============================ logging ===============================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ defines ===============================

IPADDRESS1 = 'aaaa::1'
IPADDRESS2 = 'aaaa::2'

#============================ fixtures ==============================

#============================ helpers ===============================

#============================ tests =================================

def test_dummy(logFixture):
    coap1 = coap.coap(ipAddress=IPADDRESS1,testing=True)
    coap2 = coap.coap(ipAddress=IPADDRESS2,testing=True)
    
    