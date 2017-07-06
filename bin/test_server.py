import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import threading
import binascii
from   coap   import    coap,                            \
                        coapResource,                    \
                        coapDefines         as d,        \
                        coapObjectSecurity  as oscoap
import logging_setup

class testResource(coapResource.coapResource):
    
    def __init__(self):
        # initialize parent class
        coapResource.coapResource.__init__(
            self,
            path = 'test',
        )
    
    def GET(self,options=[]):
        
        print 'GET received'
        
        respCode        = d.COAP_RC_2_05_CONTENT
        respOptions     = []
        respPayload     = [ord(b) for b in 'hello world 1 2 3 4 5 6 7 8 9 0']
        
        return (respCode,respOptions,respPayload)

# open
c = coap.coap(ipAddress='::1')

testResource = testResource()

context = oscoap.SecurityContext(masterSecret   = binascii.unhexlify('000102030405060708090A0B0C0D0E0F'),
                                 senderID       = binascii.unhexlify('736572766572'),
                                 recipientID    = binascii.unhexlify('636c69656e74'),
                                 aeadAlgorithm  = oscoap.AES_CCM_16_64_128())

# add resource - context binding with authorized methods
testResource.addSecurityBinding((context, d.METHOD_ALL))

# install resource
c.addResource(testResource)

for t in threading.enumerate():
    print t.name

# let the server run
raw_input('\n\nServer running. Press Enter to close.\n\n')

# close
c.close()
