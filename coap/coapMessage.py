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

def buildMessage(type,token,code,messageId,options,payload=[]):
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
    message += [d.COAP_VERSION<<6 | type<<4 | TKL]
    message += [code]
    message += u.int2buf(messageId,2)
    message += u.int2buf(token,TKL)
    
    # options
    options  = sortOptions(options)
    lastOptionNum = 0
    for option in options:
        assert option.optionNumber>=lastOptionNum
        message += option.toBytes(lastOptionNum)
        lastOptionNum = option.optionNumber
    
    # payload
    if payload:
        message += [d.COAP_PAYLOAD_MARKER]
    message += payload
    
    return message

def parseMessage(message):
    
    returnVal = {}
    
    # header
    if len(message<4):
        raise messageFormatError('message to short, {0} bytes: not space for header'.format(len(message)))
    returnVal['version']     = (message[0]>>6)&0x03
    if returnVal['version']!=d.COAP_VERSION:
        raise messageFormatError('invalid CoAP version {0}'.format(returnVal['version']))
    returnVal['type']        = (message[0]>>4)&0x03
    if returnVal['type'] not in d.TYPE_ALL:
        raise messageFormatError('invalid message type {0}'.format(returnVal['type']))
    TKL  = message[0]&0x0f
    if TKL>8:
        raise messageFormatError('TKL too large {0}'.format(TKL))
    returnVal['messageId']   = u.buf2int(message[2:4])
    message = message[4:]
    
    # token
    if len(message<TKL):
        raise messageFormatError('message to short, {0} bytes: not space for token'.format(len(message)))
    token  = u.buf2int(message[:TKL])
    message = message[TKL:]
    
    # options
    raise NotImplementedError()
    
    # payload
    raise NotImplementedError()
    
    return parsedMessage