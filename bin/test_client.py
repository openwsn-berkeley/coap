import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import logging_setup
from   coap import coap

SERVER_IP = '::1'

# open
c = coap.coap()

# retrieve value of 'test' resource
p = c.GET('coap://[{0}]/test'.format(SERVER_IP),)
print p

# close
c.close()

raw_input("Done. Press enter to close.")
