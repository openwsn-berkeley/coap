
#============================ path ============================================

import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

#============================ logging =========================================
import logging
import logging.handlers

fileLogger = logging.handlers.RotatingFileHandler(
   filename    = 'test.log',
   mode        = 'w',
   backupCount = 5,
)
fileLogger.setFormatter(
    logging.Formatter(
        '%(asctime)s [%(name)s:%(levelname)s] %(message)s'
    )
)

consoleLogger = logging.StreamHandler()
consoleLogger.setLevel(logging.CRITICAL)

for loggerName in [
        'coap',
        'coapUri',
        'coapTransmitter',
        'coapMessage',
        'socketUdpReal',
    ]:
    temp = logging.getLogger(loggerName)
    temp.setLevel(logging.DEBUG)
    temp.addHandler(fileLogger)
    temp.addHandler(consoleLogger)
