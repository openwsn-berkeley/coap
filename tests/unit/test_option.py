import logging
import testUtils as u

from coap import coapOption  as o, \
                 coapDefines as d

import pytest

#============================ logging ===============================

log = logging.getLogger(u.getMyLoggerName())
log.addHandler(u.NullHandler())

#============================ defines ===============================

#============================ fixtures ==============================

OPTIONMAPPING = [
    (
        o.UriPath(path='a'*12),
        0,
        tuple([(d.OPTION_NUM_URIPATH<<4)|12]+([ord('a')]*12)),
    ),
    (
        o.UriPath(path='a'*13),
        0,
        tuple([(d.OPTION_NUM_URIPATH<<4)|13]+[0]+([ord('a')]*13)),
    ),
    (
        o.UriPath(path='a'*14),
        0,
        tuple([(d.OPTION_NUM_URIPATH<<4)|13]+[1]+([ord('a')]*14)),
    ),
    (
        o.UriPath(path='a'*268),
        0,
        tuple([(d.OPTION_NUM_URIPATH<<4)|13]+[268-13]+([ord('a')]*268)),
    ),
    (
        o.UriPath(path='a'*269),
        0,
        tuple([(d.OPTION_NUM_URIPATH<<4)|14]+[0]+[0]+([ord('a')]*269)),
    ),
    (
        o.UriPath(path='a'*270),
        0,
        tuple([(d.OPTION_NUM_URIPATH<<4)|14]+[0]+[1]+([ord('a')]*270)),
    ),
    (
        o.UriPath(path='a'*270),
        5,
        tuple([((d.OPTION_NUM_URIPATH-5)<<4)|14]+[0]+[1]+([ord('a')]*270)),
    ),
]

@pytest.fixture(params=OPTIONMAPPING)
def optionMapping(request):
    return request.param

#============================ helpers ===============================

#============================ tests =================================

def test_int2buf(logFixture, optionMapping):
    
    (option,lastOptionNum,output) = optionMapping
    
    log.debug('option:        {0}'.format(option))
    log.debug('lastOptionNum: {0}'.format(lastOptionNum))
    log.debug('output:        {0}'.format(output))
    
    result = option.toBytes(lastOptionNum=lastOptionNum)
    
    log.debug('result: {0}'.format(result))
    
    assert tuple(result)==output
