import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import threading
from   coap   import    coap,                    \
                        coapResource,            \
                        coapDefines as d
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
        respPayload     = [ord(b) for b in 'dummy response']
        
        return (respCode,respOptions,respPayload)

# open
c = coap.coap(ipAddress='::1')

# install resource
c.addResource(testResource())

for t in threading.enumerate():
    print t.name

# let the server run
raw_input('\n\nServer running. Press Enter to close.\n\n')

# close
c.close()
