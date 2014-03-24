import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapOption')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapUtils     as u
import coapException as e
import coapDefines   as d

#============================ classes =========================================

class coapOption(object):
    
    def __init__(self,optionNumber):
        
        # store params
        self.optionNumber = optionNumber
        self.length       = 0
    
    #======================== abstract methods ================================
    
    def getPayloadBytes(self):
        raise NotImplementedError()
    
    #======================== public ==========================================
    
    def toBytes(self,lastOptionNum):
        
        payload    = self.getPayloadBytes()
        delta      = self.optionNumber-lastOptionNum
        
        # optionDelta and optionDeltaExt fields
        if   delta<=12:
            optionDelta      = delta
            optionDeltaExt   = u.int2buf(    delta,0)
        elif delta<=(0xff+13):
            optionDelta      = 13
            optionDeltaExt   = u.int2buf( delta-13,1)
        elif delta<=(0xffff+269):
            optionDelta      = 14
            optionDeltaExt   = u.int2buf(delta-269,2)
        else:
            raise ValueError('delta is too large: {0}'.format(delta))
        
        # optionLength and optionLengthExt fields
        if   len(payload)<=12:
            optionLength     = len(payload)
            optionLengthExt  = u.int2buf(    len(payload),0)
        elif len(payload)<=(0xff+13):
            optionLength     = 13
            optionLengthExt  = u.int2buf( len(payload)-13,1)
        elif len(payload)<=(0xffff+269):
            optionLength     = 14
            optionLengthExt  = u.int2buf(len(payload)-269,2)
        else:
            raise ValueError('payload is too long, {0} bytes'.format(len(payload)))
        
        returnVal  = []
        returnVal += [optionDelta<<4 | optionLength]
        returnVal += optionDeltaExt
        returnVal += optionLengthExt
        returnVal += payload
        
        return returnVal

class UriPath(coapOption):
    
    def __init__(self,path):
        
        # initialize parent
        coapOption.__init__(self,d.OPTION_NUM_URIPATH)
        
        # store params
        self.path = path
    
    def __repr__(self):
        return 'UriPath(path={0})'.format(self.path)
    
    def getPayloadBytes(self):
        return [ord(b) for b in self.path]

class ContentFormat(coapOption):
    
    def __init__(self,format):
        
        assert len(format)==1
        assert format[0] in d.FORMAT_ALL
        
        # initialize parent
        coapOption.__init__(self,d.OPTION_NUM_CONTENTFORMAT)
        
        # store params
        self.format = format[0]
    
    def __repr__(self):
        return 'ContentFormat(format={0})'.format(self.format)
    
    def getPayloadBytes(self):
        return [self.format]

#============================ functions =======================================

def parseOption(message,previousOptionNumber):
    '''
    \brief Extract an option from the beginning of a message.
    
    \param[in] message              A list of bytes.
    \param[in] previousOptionNumber The option number from the previous option
        in the message; set to 0 if this is the first option.
    
    \return A tuple with the following elements:
        - element 0 is the option that was extracted. If no option was found
          (end of the options or end of the packet), None is returned.
        - element 1 is the message without the option.
    '''
    
    log.debug(
        'parseOption message={0} previousOptionNumber={1}'.format(
            u.formatBuf(message),
            previousOptionNumber,
        )
    )
    
    #==== detect end of packet
    if len(message)==0:
        message = message[1:]
        return (None,message)
    
    #==== detect payload marker
    if message[0]==d.COAP_PAYLOAD_MARKER:
        message = message[1:]
        return (None,message)
    
    #==== parse option
    
    # header
    optionDelta  = (message[0]>>4)&0x0f
    optionLength = (message[0]>>0)&0x0f
    message = message[1:]
    
    # optionDelta
    if   optionDelta<=12:
        pass
    elif optionDelta==13:
        if len(message)<1:
            raise e.messageFormatError('message to short, {0} bytes: not space for 1B optionDelta'.format(len(message)))
        optionDelta = u.buf2int(messsage[0])+13
        message = message[1:]
    elif optionDelta==14:
        if len(message)<2:
            raise e.messageFormatError('message to short, {0} bytes: not space for 2B optionDelta'.format(len(message)))
        optionDelta = u.buf2int(messsage[0:1])+269
        message = message[2:]
    else:
        raise e.messageFormatError('invalid optionDelta={0}'.format(optionDelta))
    
    log.debug('optionDelta={0}'.format(optionDelta))
    
    # optionLength
    if   optionLength<=12:
        pass
    elif optionLength==13:
        if len(message)<1:
            raise e.messageFormatError('message to short, {0} bytes: not space for 1B optionLength'.format(len(message)))
        optionLength = u.buf2int(messsage[0])+13
        message = message[1:]
    elif optionLength==14:
        if len(message)<2:
            raise e.messageFormatError('message to short, {0} bytes: not space for 2B optionLength'.format(len(message)))
        optionLength = u.buf2int(messsage[0:1])+269
        message = message[2:]
    else:
        raise e.messageFormatError('invalid optionLength={0}'.format(optionLength))
    
    log.debug('optionLength={0}'.format(optionLength))
    
    # optionValue
    if len(message)<optionLength:
        raise e.messageFormatError('message to short, {0} bytes: not space for optionValue'.format(len(message)))
    optionValue = message[:optionLength]
    message = message[optionLength:]
    
    log.debug('optionValue={0}'.format(u.formatBuf(optionValue)))
    
    #===== create option
    optionNumber = previousOptionNumber+optionDelta
    if optionNumber not in d.OPTION_NUM_ALL:
        raise e.messageFormatError('invalid option number {0}'.format(optionNumber))
    
    if optionNumber==d.OPTION_NUM_URIPATH:
        option = UriPath(path=''.join([chr(b) for b in optionValue]))
    if optionNumber==d.OPTION_NUM_CONTENTFORMAT:
        option = ContentFormat(format=optionValue)
    else:
        raise NotImplementedError('option {0} not implemented'.format(optionNumber))
    
    return (option,message)