import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapMessage')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapOption         as o
import coapUtils          as u
import coapException      as e
import coapDefines        as d
import coapObjectSecurity as oscoap

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

def buildMessage(msgtype,token,code,messageId,options=[],payload=[],securityContext=None,partialIV=None):
    assert msgtype in d.TYPE_ALL
    assert code in d.METHOD_ALL+d.COAP_RC_ALL
    
    message   = []

    TKL = 0
    if token:
        # determine token length
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

    if securityContext:
        # invoke oscoap to protect the message
        (outerOptions, newPayload) = oscoap.protectMessage(context=securityContext,
                                                           version = d.COAP_VERSION,
                                                           code = code,
                                                           options = options,
                                                           payload = payload,
                                                           partialIV=partialIV)
    else:
        (outerOptions, newPayload) = (options, payload)

    # add encoded options
    message += encodeOptions(outerOptions)

    # add payload
    message += encodePayload(newPayload)
    
    return message

def parseMessage(message):
    
    returnVal = {}
    
    # header
    if len(message)<4:
        raise e.messageFormatError('message too short, {0} bytes: no space for header'.format(len(message)))
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
        raise e.messageFormatError('message too short, {0} bytes: no space for token'.format(len(message)))
    if TKL:
        returnVal['token']       = u.buf2int(message[:TKL])
        message = message[TKL:]
    else:
        returnVal['token'] = None
    
    # outer options and payload/ciphertext
    (returnVal['options'], payload) = decodeOptionsAndPayload(message)

    # if object security option is present decode the value in order to be able to decrypt the message
    objectSecurity = oscoap.objectSecurityOptionLookUp(returnVal['options'])
    if objectSecurity:
        oscoapDict = oscoap.parseObjectSecurity(objectSecurity.getPayloadBytes(), payload)
        objectSecurity.setKid(oscoapDict['kid'])
        returnVal.update(oscoapDict)
    else:
        returnVal['payload'] = payload

    
    log.debug('parsed message: {0}'.format(returnVal))
    
    return returnVal

def encodeOptions(options, lastOptionNum=0):
    encoded = []
    for option in options:
        assert option.optionNumber>=lastOptionNum
        encoded += option.toBytes(lastOptionNum)
        lastOptionNum = option.optionNumber
    return encoded

def decodeOptionsAndPayload(rawbytes, currentOptionNumber = 0):
    options = []
    while True:
        (option,rawbytes)     = o.parseOption(rawbytes, currentOptionNumber)
        if not option:
            break
        options += [option]
        currentOptionNumber  = option.optionNumber

    return (options, rawbytes)

def encodePayload(payload):
    encoded = []
    if payload:
        encoded += [d.COAP_PAYLOAD_MARKER]
        encoded += payload
    return encoded