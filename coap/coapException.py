import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapException')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

class coapException(Exception):
    
    def __init__(self,reason=''):
        
        assert type(reason)==str
        
        # store params
        self.reason   = reason
    
    def __str__(self):
        return self.reason

#============================ timeout =========================================

class coapTimeout(coapException):
    pass

#============================ formatting ======================================

class coapMalformattedUri(coapException):
    pass

class messageFormatError(coapException):
    pass

#============================ return codes ====================================

class coapRc(coapException):
    
    def __init__(self,rc,description=None):
        assert isinstance(rc,tuple)==tuple
        assert len(rc)==2
        for i in range(2):
           assert type(rc(i))==int
        if description:
           assert type(description)==str
        
        # store params
        self.rc          = rc
        self.description = description

#==== success

class coapRcCreated(coapRc):
    def __init__(self):
        coapRc.__init__(self,(2,01))

class coapRcDeleted(coapRc):
    def __init__(self):
        coapRc.__init__(self,(2,02))

class coapRcValid(coapRc):
    def __init__(self):
        coapRc.__init__(self,(2,03))

class coapRcChanged(coapRc):
    def __init__(self):
        coapRc.__init__(self,(2,04))

class coapRcContent(coapRc):
    def __init__(self):
        coapRc.__init__(self,(2,05))

#==== client error

class coapRcBadRequest(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,00))

class coapRcUnauthorized(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,01))

class coapRcBadOption(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,02))

class coapRcForbidden(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,03))

class coapRcNotFound(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,04))

class coapRcMethodNotAllowed(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,05))

class coapRcMethodNotAcceptable(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,06))

class coapRcPreconditionFailed(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,12))

class coapRcRequestEntityTooLarge(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,13))

class coapRcUnsupportedContentFormat(coapRc):
    def __init__(self):
        coapRc.__init__(self,(4,15))

#===== server error

class coapRcInternalServerError(coapRc):
    def __init__(self):
        coapRc.__init__(self,(5,00))

class coapRcNotImplemented(coapRc):
    def __init__(self):
        coapRc.__init__(self,(5,01))

class coapRcBadGateway(coapRc):
    def __init__(self):
        coapRc.__init__(self,(5,02))

class coapRcServiceUnavailable(coapRc):
    def __init__(self):
        coapRc.__init__(self,(5,03))

class coapRcGatewayTimeout(coapRc):
    def __init__(self):
        coapRc.__init__(self,(5,04))

class coapRcProxyingNotSupported(coapRc):
    def __init__(self):
        coapRc.__init__(self,(5,05))
