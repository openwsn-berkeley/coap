import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapObjectSecurity')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

def protectMessage(header, options, payload=[]):
    return payload

