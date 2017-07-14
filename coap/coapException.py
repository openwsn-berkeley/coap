import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapException')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapDefines as d

class coapException(Exception):
    
    def __init__(self,reason=''):
        
        assert type(reason)==str
        
        # store params
        self.reason   = reason
    
    def __str__(self):
        return '{0}(reason={1})'.format(self.__class__.__name__,self.reason)

#============================ timeout =========================================

class coapDelayedResponse(coapException):
    pass

#============================ timeout =========================================

class coapTimeout(coapException):
    pass

#============================ formatting ======================================

class coapMalformattedUri(coapException):
    pass

class messageFormatError(coapException):
    pass

#======================== oscoap verification =================================

class oscoapError(coapException):
    pass

#============================ return codes ====================================

class coapRc(coapException):
    rc=None
    def __init__(self,reason=''):
        
        assert self.rc
        
        # initialize parent
        coapException.__init__(self,reason=reason)

class coapRcFactory(object):
    def __new__(klass,rc):
        coapRcClasses = []
        for (i,j) in globals().iteritems():
            try:
                if issubclass(j,coapRc):
                    coapRcClasses.append(j)
            except TypeError:
                pass
        for coapRcClass in coapRcClasses:
            if coapRcClass.rc==rc:
                return coapRcClass()
        return coapRcUnknown(rc)

class coapRcUnknown(coapRc):
    def __init__(self,rc):
        self.rc = rc

#==== success

class coapRcCreated(coapRc):
    rc = d.COAP_RC_2_01_CREATED

class coapRcDeleted(coapRc):
    rc = d.COAP_RC_2_02_DELETED

class coapRcValid(coapRc):
    rc = d.COAP_RC_2_03_VALID

class coapRcChanged(coapRc):
    rc = d.COAP_RC_2_04_CHANGED

class coapRcContent(coapRc):
    rc = d.COAP_RC_2_05_CONTENT

#==== client error

class coapRcBadRequest(coapRc):
    rc = d.COAP_RC_4_00_BADREQUEST

class coapRcUnauthorized(coapRc):
    rc = d.COAP_RC_4_01_UNAUTHORIZED

class coapRcBadOption(coapRc):
    rc = d.COAP_RC_4_02_BADOPTION

class coapRcForbidden(coapRc):
    rc = d.COAP_RC_4_03_FORBIDDEN

class coapRcNotFound(coapRc):
    rc = d.COAP_RC_4_04_NOTFOUND

class coapRcMethodNotAllowed(coapRc):
    rc = d.COAP_RC_4_05_METHODNOTALLOWED

class coapRcMethodNotAcceptable(coapRc):
    rc = d.COAP_RC_4_06_NOTACCEPTABLE

class coapRcPreconditionFailed(coapRc):
    rc = d.COAP_RC_4_12_PRECONDITIONFAILED

class coapRcRequestEntityTooLarge(coapRc):
    rc = d.COAP_RC_4_13_REQUESTENTITYTOOLARGE

class coapRcUnsupportedContentFormat(coapRc):
    rc = d.COAP_RC_4_15_UNSUPPORTEDCONTENTFORMAT

#===== server error

class coapRcInternalServerError(coapRc):
    rc = d.COAP_RC_5_00_INTERNALSERVERERROR

class coapRcNotImplemented(coapRc):
    rc = d.COAP_RC_5_01_NOTIMPLEMENTED

class coapRcBadGateway(coapRc):
    rc = d.COAP_RC_5_02_BADGATEWAY

class coapRcServiceUnavailable(coapRc):
    rc = d.COAP_RC_5_03_SERVICEUNAVAILABLE

class coapRcGatewayTimeout(coapRc):
    rc = d.COAP_RC_5_04_GATEWAYTIMEOUT

class coapRcProxyingNotSupported(coapRc):
    rc = d.COAP_RC_5_05_PROXYINGNOTSUPPORTED
