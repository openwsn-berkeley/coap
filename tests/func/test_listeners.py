import logging
import testUtils as utils

import time
import threading

from coap import coap, \
                 coapDefines

#============================ logging ===============================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ defines ===============================

IPADDRESS1 = 'aaaa::1'
IPADDRESS2 = 'aaaa::2'

#============================ fixtures ==============================

#============================ helpers ===============================

#============================ tests =================================

def test_startStop(logFixture):
    
    for _ in range(5):
        
        assert len(threading.enumerate())==1
        
        # start two coap endpoints
        coap1 = coap.coap(ipAddress=IPADDRESS1,testing=True)
        coap2 = coap.coap(ipAddress=IPADDRESS2,testing=True)
        
        # let them live a bit
        time.sleep(0.500)
        
        assert len(threading.enumerate())==3
        
        # close them
        coap1.close()
        coap2.close()
        
        time.sleep(0.500)
        assert len(threading.enumerate())==1
    
def test_socketUdpComunication(logFixture):
    
    # start two coap endpoints
    coap1 = coap.coap(ipAddress=IPADDRESS1,testing=True)
    coap2 = coap.coap(ipAddress=IPADDRESS2,testing=True)
    
    # send coap1->coap2
    for _ in range(30):
        coap1.socketUdp.sendUdp(
            destIp   = IPADDRESS2,
            destPort = coapDefines.DEFAULT_UDP_PORT,
            msg      = [0x00,0x01]
        )
    
    # verify stats
    assert coap1.socketUdp.getStats()=={
        'numTx': 30,
        'numRx': 0,
    }
    assert coap2.socketUdp.getStats()=={
        'numTx': 0,
        'numRx': 30,
    }
    
    # close them
    coap1.close()
    coap2.close()
    
    time.sleep(0.500)
    assert len(threading.enumerate())==1