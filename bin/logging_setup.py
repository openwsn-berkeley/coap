
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
consoleLogger.setLevel(logging.DEBUG)

for loggerName in [
        'coap',
        'coapOption',
        'coapUri',
        'coapTransmitter',
        'coapMessage',
        'socketUdpReal',
    ]:
    temp = logging.getLogger(loggerName)
    temp.setLevel(logging.DEBUG)
    temp.addHandler(fileLogger)
    temp.addHandler(consoleLogger)
