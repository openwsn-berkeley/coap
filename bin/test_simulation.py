import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import logging_setup
from   coap import coap

MOTE_IP = 'bbbb::1415:92cc:0:2'

# open
c = coap.coap()

# speed up timeouts
c.ackTimeout  = 2 # sec
c.respTimeout = 2 # sec

# get status of LED
p = c.GET('coap://[{0}]/l'.format(MOTE_IP),)
print chr(p[0])

# toggle debug LED
p = c.PUT(
    'coap://[{0}]/l'.format(MOTE_IP),
    payload = [ord('2')],
)

# read status of debug LED
p = c.GET('coap://[{0}]/l'.format(MOTE_IP))
print chr(p[0])

# close
c.close()

raw_input("Done. Press enter to close.")
