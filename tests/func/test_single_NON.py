import logging
import testUtils as utils

import time
import threading

from coap import coap, \
                 coapDefines as d, \
                 coapResource

#============================ logging ===============================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ defines ===============================

IPADDRESS1 = 'aaaa::1'
IPADDRESS2 = 'aaaa::2'

RESOURCE   = 'res'
DUMMYVAL   = [0x00,0x01,0x02]

#============================ fixtures ========================================

#============================ helpers =========================================

class dummyResource(coapResource.coapResource):
    
    def __init__(self):
        # initialize parent class
        coapResource.coapResource.__init__(
            self,
            path = RESOURCE,
        )
    
    #======================== parent methods ==================================
    
    def GET(self,options=[]):
        log.debug('dummyResource GET')
        
        respCode        = d.COAP_RC_2_05_CONTENT
        respOptions     = []
        respPayload     = DUMMYVAL
        
        return (respCode,respOptions,respPayload)
    
#============================ tests ===========================================

def test_GET(logFixture,snoopyDispatcher):
    
    # start two coap endpoints
    coap1 = coap.coap(ipAddress=IPADDRESS1,testing=True)
    coap2 = coap.coap(ipAddress=IPADDRESS2,testing=True)
    
    # create new resource
    newResource = dummyResource()
    
    # install resource on coap1
    coap1.addResource(newResource)
    
    # have coap2 do a get
    reply = coap2.GET(
        uri         = 'coap://[{0}]:{1}/{2}/'.format(IPADDRESS1,d.DEFAULT_UDP_PORT,RESOURCE),
        confirmable = False,
    )
    assert reply==DUMMYVAL
    
    # close them
    coap1.close()
    coap2.close()
    
    time.sleep(0.500)
    assert len(threading.enumerate())==1
