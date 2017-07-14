import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,'..'))

import logging
import logging.handlers
import threading
import time

import pytest

import binascii

import testUtils        as utils
import snoopyDispatcher as snoopyDis
from coap import coap, \
                 coapDefines        as d,       \
                 coapResource,                  \
                 coapObjectSecurity as oscoap

#============================ logging =========================================

log = logging.getLogger('conftest')
log.addHandler(utils.NullHandler())

#============================ defines =========================================

LOG_MODULES = [
    'conftest',
    'coap',
    'coapUri',
    'coapOption',
    'coapMessage',
    'coapResource',
    'coapTransmitter',
    'coapUtils',
    'socketUdp',
    'socketUdpReal',
    'socketUdpDispatcher',
    'snoopyDispatcher',
]

IPADDRESS1          = 'aaaa::1'
IPADDRESS2          = 'aaaa::2'

RESOURCE            = 'res'
DUMMYVAL            = [0x00,0x01,0x02]

OSCOAPMASTERSECRET  = binascii.unhexlify('000102030405060708090A0B0C0D0E0F')
OSCOAPSERVERID      = binascii.unhexlify('00212ffffeb56e1001')
OSCOAPCLIENTID      = binascii.unhexlify('00212ffffeb56e1000')

#============================ fixtures ========================================

#===== logFixture

def getTestModuleName(request):
    return request.module.__name__.split('.')[-1]

def getTestFunctionName(request):
    return request.function.__name__.split('.')[-1]

def loggingSetup(request):
    moduleName = getTestModuleName(request)
    
    # create logHandler
    logHandler = logging.handlers.RotatingFileHandler(
       filename    = '{0}.log'.format(moduleName),
       mode        = 'w',
       backupCount = 5,
    )
    logHandler.setFormatter(
        logging.Formatter(
            '%(asctime)s [%(name)s:%(levelname)s] %(message)s'
        )
    )
    
    # setup logging
    for loggerName in [moduleName]+LOG_MODULES:
        temp = logging.getLogger(loggerName)
        temp.setLevel(logging.DEBUG)
        temp.addHandler(logHandler)
    
    # log
    log.debug("\n\n---------- loggingSetup")

def loggingTeardown(request):
    moduleName = getTestModuleName(request)
    
    # print threads
    output         = []
    output        += ['threads:']
    for t in threading.enumerate():
        output    += ['- {0}'.format(t.name)]
    output         = '\n'.join(output)
    log.debug(output)
    
    # log
    log.debug("\n\n---------- loggingTeardown")
    
    # teardown logging
    for loggerName in [moduleName]+LOG_MODULES:
        temp = logging.getLogger(loggerName)
        temp.handler = []

@pytest.fixture(scope='module')
def logFixtureModule(request):
    loggingSetup(request)
    f = lambda : loggingTeardown(request)
    request.addfinalizer(f)

@pytest.fixture(scope='function')
def logFixture(logFixtureModule,request):
    
    # log
    log.debug('\n\n---------- {0}'.format(getTestFunctionName(request)))
    
    return logFixtureModule

#===== snoopyDispatcher

def snoppyTeardown(snoppy):
    snoppy.close()

@pytest.fixture(scope='module')
def snoopyDispatcher(request):
    moduleName = getTestModuleName(request)
    snoopy = snoopyDis.snoopyDispatcher('{0}.pcap'.format(moduleName))
    f = lambda : snoppyTeardown(snoopy)
    request.addfinalizer(f)

#===== twoEndPoints

class dummyResource(coapResource.coapResource):
    
    def __init__(self):
        # initialize parent class
        coapResource.coapResource.__init__(
            self,
            path = RESOURCE,
        )
    
    #======================== parent methods ==================================
    
    def GET(self,options=[]):
        log.debug('dummyResource GET')
        
        respCode        = d.COAP_RC_2_05_CONTENT
        respOptions     = []
        respPayload     = DUMMYVAL
        
        time.sleep(0.500)
        
        return (respCode,respOptions,respPayload)

def twoEndPointsTeardown(coap1,coap2):
    coap1.close()
    coap2.close()
    
    time.sleep(0.500)
    assert len(threading.enumerate())==1

SECURITYFIXTURE = [
    False,
    True,
]

@pytest.fixture(params=SECURITYFIXTURE, scope='function')
def twoEndPoints(request):
    
    # start two coap endpoints
    coap1 = coap.coap(ipAddress=IPADDRESS1, testing=True)
    coap2 = coap.coap(ipAddress=IPADDRESS2, testing=True)

    # create new resource
    newResource = dummyResource()

    if request.param == True: # if testing with security, protect the resource with security context
        context = oscoap.SecurityContext(masterSecret=OSCOAPMASTERSECRET,
                                         senderID=OSCOAPCLIENTID,
                                         recipientID=OSCOAPSERVERID)

        # add resource - context binding with authorized methods
        newResource.addSecurityBinding((context, d.METHOD_ALL))

    # install resource on coap1
    coap1.addResource(newResource)

    f = lambda: twoEndPointsTeardown(coap1, coap2)
    request.addfinalizer(f)

    return (coap1, coap2, request.param)


#===== confirmableFixture

CONFIRMABLEFIXTURE = [
   True,
   False,
]

@pytest.fixture(params=CONFIRMABLEFIXTURE)
def confirmableFixture(request):
    return request.param