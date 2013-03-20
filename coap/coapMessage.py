import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapMessage')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapDefines   as d
import coapException as e
import coapOption    as o
import coapUtils     as u

def sortOptions(options):
    # TODO implement sorting when more options are implemented
    return options

def buildMessage(type,token,code,messageId,options,payload):
    assert type in d.TYPE_ALL
    assert code in d.METHOD_ALL
    
    message   = []
    
    # determine token length
    TKL = None
    for tokenLen in range(1,8+1):
        if token < (1<<(8*tokenLen)):
            TKL = tokenLen
            break
    if not TKL:
        raise ValueError('token {0} too long'.format(token))
    
    # header
    message += [COAP_VERSION<<6 | type<<4 | TKL]
    message += [code]
    message += u.int2buf(messageId,2)
    message += u.int2buf(token,TKL)
    
    # options
    options  = sortOptions(options)
    lastOptionNum = 0
    for option in options:
        assert option.optionNumber>=lastOptionNum
        message += [option.toBytes(lastOptionNum)]
        lastOptionNum = option.optionNumber
    
    # payload
    return message