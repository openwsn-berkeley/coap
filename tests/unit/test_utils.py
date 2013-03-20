import logging
import testUtils

from coap import coapUtils

import pytest

#============================ logging ===============================

log = logging.getLogger(testUtils.getMyLoggerName())
log.addHandler(testUtils.NullHandler())

#============================ defines ===============================

#============================ fixtures ==============================

VALIDINT2BUF = [
    (
        0x1234,
        0,
        (),
    ),
    (
        0x1234,
        2,
        (0x12,0x34),
    ),
    (
        0x1234,
        3,
        (0x00,0x12,0x34),
    ),
]

@pytest.fixture(params=VALIDINT2BUF)
def validint2buf(request):
    return request.param

#============================ helpers ===============================

#============================ tests =================================

def test_int2buf(logFixture, validint2buf):
    
    (val,len,output) = validint2buf
    
    log.debug('val:    {0}'.format(val))
    log.debug('len:    {0}'.format(len))
    log.debug('output: {0}'.format(output))
    
    result = coapUtils.int2buf(val,len)
    
    log.debug('result: {0}'.format(result))
    
    assert tuple(result)==output
