import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapMessage')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapOption    as o
import coapUtils     as u
import coapException as e
import coapDefines   as d

def sortOptions(options):
    # TODO implement sorting when more options are implemented
    return options

'''
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver| T |  TKL  |      Code     |          Message ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''

def buildMessage(msgtype,token,code,messageId,options=[],payload=[]):
    assert msgtype in d.TYPE_ALL
    assert code in d.METHOD_ALL+d.COAP_RC_ALL
    
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
    message += [d.COAP_VERSION<<6 | msgtype<<4 | TKL]
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
    if len(message)<4:
        raise e.messageFormatError('message to short, {0} bytes: not space for header'.format(len(message)))
    returnVal['version']     = (message[0]>>6)&0x03
    if returnVal['version']!=d.COAP_VERSION:
        raise e.messageFormatError('invalid CoAP version {0}'.format(returnVal['version']))
    returnVal['type']        = (message[0]>>4)&0x03
    if returnVal['type'] not in d.TYPE_ALL:
        raise e.messageFormatError('invalid message type {0}'.format(returnVal['type']))
    TKL  = message[0]&0x0f
    if TKL>8:
        raise e.messageFormatError('TKL too large {0}'.format(TKL))
    returnVal['code']        = message[1]
    returnVal['messageId']   = u.buf2int(message[2:4])
    message = message[4:]
    
    # token
    if len(message)<TKL:
        raise e.messageFormatError('message to short, {0} bytes: not space for token'.format(len(message)))
    returnVal['token']       = u.buf2int(message[:TKL])
    message = message[TKL:]
    
    # options
    returnVal['options']     = []
    currentOptionNumber      = 0
    while True:
        (option,message)     = o.parseOption(message,currentOptionNumber)
        if not option:
            break
        returnVal['options']+= [option]
        currentOptionNumber  = option.optionNumber
    
    # payload
    returnVal['payload']     = message
    
    log.debug('parsed message: {0}'.format(returnVal))
    
    return returnVal
