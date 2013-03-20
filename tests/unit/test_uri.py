import logging
import testUtils as u

from coap import coapOption, \
                 coapDefines as d, \
                 coapUri

import pytest

#============================ logging ===============================

log = logging.getLogger(u.getMyLoggerName())
log.addHandler(u.NullHandler())

#============================ defines ===============================

#============================ fixtures ==============================

VALIDURI = [
    (
        'coap://[aaaa::1]/',
        (
            'aaaa::1',
            d.DEFAULT_UDP_PORT,
            (),
        )
    ),
    (
        'coap://[aaaa::1]/test',
        (
            'aaaa::1',
            d.DEFAULT_UDP_PORT,
            (
                coapOption.UriPath(path='test'),
            ),
        )
    ),
    (
        'coap://[aaaa::1]:1234/test',
        (
            'aaaa::1',
            1234,
            (
                coapOption.UriPath(path='test'),
            ),
        )
    ),
    (
        'coap://[aaaa::1]:1234/test1/test2',
        (
            'aaaa::1',
            1234,
            (
                coapOption.UriPath(path='test1'),
                coapOption.UriPath(path='test2'),
            ),
        )
    ),
]

@pytest.fixture(params=VALIDURI)
def validUri(request):
    return request.param

#============================ helpers ===============================

#============================ tests =================================

def test_uri2options(logFixture, validUri):
    
    (input,output) = validUri
    
    log.debug('input:  {0}'.format(input))
    log.debug('output: {0}'.format(output))
    
    result = coapUri.uri2options(input)
    
    log.debug('result: {0}'.format(result))
    
    assert len(result)==len(output)
    assert   result[0]==output[0]
    assert   result[1]==output[1]
    assert len(result[2])==len(output[2])
    for (resultPath,outputPath) in zip(result[2],output[2]):
       assert repr(resultPath)==repr(outputPath)
