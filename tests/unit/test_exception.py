import logging
import testUtils

from coap import coapException as e, \
                 coapDefines as d

import pytest

#============================ logging ===============================

log = logging.getLogger(testUtils.getMyLoggerName())
log.addHandler(testUtils.NullHandler())

#============================ fixtures ==============================

RCVALANDRCCLASS = [
    (d.COAP_RC_2_01_CREATED,                     e.coapRcCreated),
    (d.COAP_RC_2_02_DELETED,                     e.coapRcDeleted),
    (d.COAP_RC_2_03_VALID,                       e.coapRcValid),
    (d.COAP_RC_2_04_CHANGED,                     e.coapRcChanged),
    (d.COAP_RC_2_05_CONTENT,                     e.coapRcContent),
    (d.COAP_RC_4_00_BADREQUEST,                  e.coapRcBadRequest),
    (d.COAP_RC_4_01_UNAUTHORIZED,                e.coapRcUnauthorized),
    (d.COAP_RC_4_02_BADOPTION,                   e.coapRcBadOption),
    (d.COAP_RC_4_03_FORBIDDEN,                   e.coapRcForbidden),
    (d.COAP_RC_4_04_NOTFOUND,                    e.coapRcNotFound),
    (d.COAP_RC_4_05_METHODNOTALLOWED,            e.coapRcMethodNotAllowed),
    (d.COAP_RC_4_06_NOTACCEPTABLE,               e.coapRcMethodNotAcceptable),
    (d.COAP_RC_4_12_PRECONDITIONFAILED,          e.coapRcPreconditionFailed),
    (d.COAP_RC_4_13_REQUESTENTITYTOOLARGE,       e.coapRcRequestEntityTooLarge),
    (d.COAP_RC_4_15_UNSUPPORTEDCONTENTFORMAT,    e.coapRcUnsupportedContentFormat),
    (d.COAP_RC_5_00_INTERNALSERVERERROR,         e.coapRcInternalServerError),
    (d.COAP_RC_5_01_NOTIMPLEMENTED,              e.coapRcNotImplemented),
    (d.COAP_RC_5_02_BADGATEWAY,                  e.coapRcBadGateway),
    (d.COAP_RC_5_03_SERVICEUNAVAILABLE,          e.coapRcServiceUnavailable),
    (d.COAP_RC_5_04_GATEWAYTIMEOUT,              e.coapRcGatewayTimeout),
    (d.COAP_RC_5_05_PROXYINGNOTSUPPORTED,        e.coapRcProxyingNotSupported),
]

@pytest.fixture(params=RCVALANDRCCLASS)
def rcValAndRcClass(request):
    return request.param

#============================ tests =================================

def test_factory_successful(logFixture,rcValAndRcClass):
    
    (rcVal,rcClass) = rcValAndRcClass
    
    assert isinstance(e.coapRcFactory(rcVal),rcClass)

def test_factory_unknown(logFixture):
    
    rc = e.coapRcFactory(1000)
    assert isinstance(rc,e.coapRcUnknown)
    assert rc.rc==1000
    
    