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

context = oscoap.SecurityContext(masterSecret   = binascii.unhexlify('0102030405060708090a0b0c0d0e0f10'),
                                 masterSalt     = binascii.unhexlify('9e7ca92223786340'),
                                 senderID       = binascii.unhexlify(''),
                                 recipientID    = binascii.unhexlify('01'),
                                 idContext      = binascii.unhexlify('37cbf3210017a2d3'),
                                 aeadAlgorithm  = oscoap.AES_CCM_16_64_128())

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
