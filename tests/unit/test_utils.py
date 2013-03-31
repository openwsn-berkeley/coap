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

VALIDIPv6ADDRSTR2BYTES = [
    (
        'aaaa::1',
        tuple([0xaa,0xaa]+[0x00]*(16-2-1)+[0x01])
    ),
    (
        '1:2:3:4:5:6:7:8',
        tuple([0x00,0x01,0x00,0x02,0x00,0x03,0x00,0x04,
               0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08])
    ),
    (
        '1234:002:03:0004:005:06:7:8',
        tuple([0x12,0x34,0x00,0x02,0x00,0x03,0x00,0x04,
               0x00,0x05,0x00,0x06,0x00,0x07,0x00,0x08])
    ),
]

@pytest.fixture(params=VALIDIPv6ADDRSTR2BYTES)
def validIpv6AddrStr2Bytes(request):
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

def test_buf2int(logFixture, validint2buf):
    
    (val,_,buf) = validint2buf
    
    if not buf:
        return
    
    log.debug('val:    {0}'.format(val))
    log.debug('buf:    {0}'.format(buf))
    
    result = coapUtils.buf2int(buf)
    
    log.debug('result: {0}'.format(result))
    
    assert result==val

def test_ipv6AddrString2Bytes(logFixture, validIpv6AddrStr2Bytes):
    
    (ipv6String,ipv6Bytes) = validIpv6AddrStr2Bytes
    ipv6Bytes = list(ipv6Bytes)
    
    log.debug('ipv6String: {0}'.format(ipv6String))
    log.debug('ipv6Bytes:  {0}'.format(coapUtils.formatBuf(ipv6Bytes)))
    
    result = coapUtils.ipv6AddrString2Bytes(ipv6String)
    
    log.debug('result:     {0}'.format(coapUtils.formatBuf(result)))
    
    assert result==ipv6Bytes