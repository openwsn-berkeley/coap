import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import time

from   coap import coap
import logging_setup

SERVER_IP = '::1'

# open
c = coap.coap(udpPort=5000)

# retrieve value of 'test' resource
p = c.GET('coap://[{0}]/test'.format(SERVER_IP),)
print '====='
print ''.join([chr(b) for b in p])
print '====='

# close
c.close()

time.sleep(0.500)

raw_input("Done. Press enter to close.")
