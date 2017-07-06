import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import time
import binascii

from   coap import coap
from coap import coapOption           as o
from coap import coapObjectSecurity   as oscoap

import logging_setup

SERVER_IP = '::1'

# open
c = coap.coap(udpPort=5000)

context = oscoap.SecurityContext(masterSecret=binascii.unhexlify('000102030405060708090A0B0C0D0E0F'),
                                 senderID=binascii.unhexlify('636c69656e74'),
                                 recipientID=binascii.unhexlify('736572766572'),
                                 aeadAlgorithm=oscoap.AES_CCM_16_64_128())

objectSecurity = o.ObjectSecurity(context=context)

try:
    # retrieve value of 'test' resource
    p = c.GET('coap://[{0}]/test'.format(SERVER_IP),
              confirmable=True,
              options=[objectSecurity])

    print '====='
    print ''.join([chr(b) for b in p])
    print '====='
except Exception as err:
    print err

# close
c.close()

time.sleep(0.500)

raw_input("Done. Press enter to close.")
