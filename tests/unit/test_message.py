import logging
import testUtils

from coap import coapOption  as o, \
                 coapDefines as d, \
                 coapMessage as m, \
                 coapUtils   as u

import pytest

#============================ logging ===============================

log = logging.getLogger(testUtils.getMyLoggerName())
log.addHandler(testUtils.NullHandler())

#============================ defines ===============================

#============================ fixtures ==============================

MESSAGEANDBYTES = [
    (
        (
            d.TYPE_NON,                                         # type
            0xaa,                                               # token
            d.METHOD_GET,                                       # code
            0xbbcc,                                             # messageId
            (                                                   # options
                o.UriPath(path='test1'),
                o.UriPath(path='test2'),
            ),
            (0xee,0xff),                                        # payload
        ),
        (
            0x51,                                               # Ver | T | TKL
            0x01,                                               # Code
            0xbb,0xcc,                                          # MessgeID
            0xaa,                                               # Token
            0xb5,ord('t'),ord('e'),ord('s'),ord('t'),ord('1'),  # Uri-Path
            0x05,ord('t'),ord('e'),ord('s'),ord('t'),ord('2'),  # Uri-Path
            0xff,                                               # payload marker
            0xee,0xff,                                          # payload
        ), 
    ),
    (
        (
            d.TYPE_NON,                                         # type
            0xaa,                                               # token
            d.METHOD_GET,                                       # code
            0xbbcc,                                             # messageId
            (                                                   # options
                o.UriPath(path='test1'),
                o.UriPath(path='test2'),
            ),
            (),                                                 # payload
        ),
        (
            0x51,                                               # Ver | T | TKL
            0x01,                                               # Code
            0xbb,0xcc,                                          # MessgeID
            0xaa,                                               # Token
            0xb5,ord('t'),ord('e'),ord('s'),ord('t'),ord('1'),  # Uri-Path
            0x05,ord('t'),ord('e'),ord('s'),ord('t'),ord('2'),  # Uri-Path
        ), 
    ),
    (
        (
            d.TYPE_NON,                                         # type
            0x1122,                                             # token
            d.METHOD_GET,                                       # code
            0xbbcc,                                             # messageId
            (                                                   # options
                o.UriPath(path='test1'),
                o.UriPath(path='test2'),
            ),
            (),                                                 # payload
        ),
        (
            0x52,                                               # Ver | T | TKL
            0x01,                                               # Code
            0xbb,0xcc,                                          # MessgeID
            0x11,0x22,                                          # Token
            0xb5,ord('t'),ord('e'),ord('s'),ord('t'),ord('1'),  # Uri-Path
            0x05,ord('t'),ord('e'),ord('s'),ord('t'),ord('2'),  # Uri-Path
        ), 
    ),
]

@pytest.fixture(params=MESSAGEANDBYTES)
def messageAndBytes(request):
    return request.param

#============================ helpers ===============================

#============================ tests =================================

def test_buildMessage(logFixture, messageAndBytes):
    
    (msg,bytes) = messageAndBytes
    
    log.debug('msg:     {0}'.format(msg))
    log.debug('bytes:   {0}'.format(u.formatBuf(bytes)))
    
    result = m.buildMessage(
        type       =      msg[0],
        token      =      msg[1],
        code       =      msg[2],
        messageId  =      msg[3],
        options    =      msg[4],
        payload    = list(msg[5]),
    )
    
    log.debug('result:  {0}'.format(u.formatBuf(result)))
    
    assert tuple(result)==bytes
