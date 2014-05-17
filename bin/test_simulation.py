import logging
import logging.handlers

from coap import coap

#============================ logging =========================================
fileLogger = logging.handlers.RotatingFileHandler(
   filename    = 'testcoap.log',
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

#============================ main ============================================

MOTE_IP = 'bbbb::1415:92cc:0:2'

c = coap.coap()

print c.respTimeout

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
