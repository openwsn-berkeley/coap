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

URIANDOPTIONS = [
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
        'coap://[bbbb::1415:92cc:0:2]/t',
        (
            'bbbb::1415:92cc:0:2',
            5683,
            (
                coapOption.UriPath(path='t'),
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
    (
        'coap://vs0.inf.ethz.ch:5683/',
        (
            'vs0.inf.ethz.ch',
            5683,
            (),
        )
    ),
    (
        'coap://vs0.inf.ethz.ch:5683/test1/test2',
        (
            'vs0.inf.ethz.ch',
            5683,
            (
                coapOption.UriPath(path='test1'),
                coapOption.UriPath(path='test2'),
            ),
        )
    ),
    (
        'coap://vs0.inf.ethz.ch:5683/test2/test3/',
        (
            'vs0.inf.ethz.ch',
            5683,
            (
                coapOption.UriPath(path='test2'),
                coapOption.UriPath(path='test3'),
            ),
        )
    ),
    (
        'coap://vs0.inf.ethz.ch/test2/test3/',
        (
            'vs0.inf.ethz.ch',
            5683,
            (
                coapOption.UriPath(path='test2'),
                coapOption.UriPath(path='test3'),
            ),
        )
    ),
    (
        'coap://www.poi1-poi2_poi3.poi4.com/test2/test3/',
        (
            'www.poi1-poi2_poi3.poi4.com',
            5683,
            (
                coapOption.UriPath(path='test2'),
                coapOption.UriPath(path='test3'),
            ),
        )
    ),
    (
        'coap://[bbbb::1415:92cc:0:3]/res/ource',
        (
            'bbbb::1415:92cc:0:3',
            5683,
            (
                coapOption.UriPath(path='res'),
                coapOption.UriPath(path='ource'),
            ),
        )
    ),
    (
        'coap://[bbbb::1415:92cc:0000:0003]/res/ource',
        (
            'bbbb::1415:92cc:0:3',
            5683,
            (
                coapOption.UriPath(path='res'),
                coapOption.UriPath(path='ource'),
            ),
        )
    ),
]

@pytest.fixture(params=URIANDOPTIONS)
def uriAndOptions(request):
    return request.param

OPTIONSANDPATH = [
    (
        (
            coapOption.UriPath(path='test1'),
            coapOption.UriPath(path='test2'),
        ),
        'test1/test2'
    ),
]

@pytest.fixture(params=OPTIONSANDPATH)
def optionsAndPath(request):
    return request.param

#============================ helpers ===============================

#============================ tests =================================

def test_uri2options(logFixture, uriAndOptions):
    
    (input,output) = uriAndOptions
    
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

def test_options2path(logFixture, optionsAndPath):
    
    (options,path) = optionsAndPath
    options = list(options)
    
    log.debug('options: {0}'.format(options))
    log.debug('path:    {0}'.format(path))
    
    result = coapUri.options2path(options)
    
    log.debug('result:  {0}'.format(result))
    
    assert result==path
