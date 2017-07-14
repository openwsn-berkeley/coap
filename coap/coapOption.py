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
    
    def __init__(self,optionNumber, oscoapClass=d.OSCOAP_CLASS_E):
        
        # store params
        self.optionNumber = optionNumber
        self.oscoapClass  = oscoapClass
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

#=== OPTION_NUM_IFMATCH

#=== OPTION_NUM_URIHOST

class UriHost(coapOption):
    def __init__(self, host):
        # initialize parent
        coapOption.__init__(self, d.OPTION_NUM_URIHOST, d.OSCOAP_CLASS_U)

        # store params
        self.host = host

    def __repr__(self):
        return 'UriHost(host={0})'.format(self.host)

    def getPayloadBytes(self):
        return [ord(b) for b in self.host]

#=== OPTION_NUM_ETAG

#=== OPTION_NUM_IFNONEMATCH

#=== OPTION_NUM_URIPORT

#=== OPTION_NUM_LOCATIONPATH

#=== OPTION_NUM_URIPATH

class UriPath(coapOption):
    
    def __init__(self,path):
        
        # initialize parent
        coapOption.__init__(self,d.OPTION_NUM_URIPATH, d.OSCOAP_CLASS_E)
        
        # store params
        self.path = path
    
    def __repr__(self):
        return 'UriPath(path={0})'.format(self.path)
    
    def getPayloadBytes(self):
        return [ord(b) for b in self.path]

#=== OPTION_NUM_CONTENTFORMAT

class ContentFormat(coapOption):
    
    def __init__(self,cformat):

        if len(cformat)==0:
            cformat = [0]
        
        assert len(cformat)==1
        assert cformat[0] in d.FORMAT_ALL
        
        # initialize parent
        coapOption.__init__(self,d.OPTION_NUM_CONTENTFORMAT, d.OSCOAP_CLASS_E)
        
        # store params
        self.format = cformat[0]
    
    def __repr__(self):
        return 'ContentFormat(format={0})'.format(self.format)
    
    def getPayloadBytes(self):
        return [self.format]

#=== OPTION_NUM_MAXAGE

#=== OPTION_NUM_URIQUERY

#=== OPTION_NUM_ACCEPT

class Accept(coapOption):
    def __init__(self, accept):
        assert len(accept) == 1
        assert accept[0] in d.FORMAT_ALL

        # initialize parent
        coapOption.__init__(self, d.OPTION_NUM_ACCEPT, d.OSCOAP_CLASS_E)

        # store params
        self.accept = accept[0]

    def __repr__(self):
        return 'Accept(format={0})'.format(self.accept)

    def getPayloadBytes(self):
        return [self.accept]


#=== OPTION_NUM_LOCATIONQUERY

#=== OPTION_NUM_BLOCK2

class Block2(coapOption):
    
    def __init__(self,num=None,m=None,szx=None,rawbytes=[]):
        
        if rawbytes:
            assert num==None
            assert m==None
            assert szx==None
        else:
            assert num!=None
            assert m!=None
            assert szx!=None
        
        # initialize parent
        coapOption.__init__(self,d.OPTION_NUM_BLOCK2, d.OSCOAP_CLASS_E)
        
        # store params
        if num:
            # values of num, m, szx specified explicitly
            self.num   = num
            self.m     = m
            self.szx   = szx
        else:
            # values of num, m, szx need to be extracted
            if   len(rawbytes)==1:
                self.num   = (rawbytes[0]>>4)&0x0f
                self.m     = (rawbytes[0]>>3)&0x01
                self.szx   = (rawbytes[0]>>0)&0x07
            elif len(rawbytes)==2:
                self.num   = rawbytes[0]<<8 | (rawbytes[1]>>4)&0x0f
                self.m     = (rawbytes[1]>>3)&0x01
                self.szx   = (rawbytes[1]>>0)&0x07
            elif len(rawbytes)==3:
                self.num   = rawbytes[0]<<16 | rawbytes[1]<<8 | (rawbytes[2]>>4)&0x0f
                self.m     = (rawbytes[2]>>3)&0x01
                self.szx   = (rawbytes[2]>>0)&0x07
            else:
                raise ValueError('unexpected Block2 len={0}'.format(len(rawbytes)))
    
    def __repr__(self):
        return 'Block2(num={0},m={1},szx={2})'.format(self.num,self.m,self.szx)
    
    def getPayloadBytes(self):
        return NotImplementedError()

#=== OPTION_NUM_BLOCK1

#=== OPTION_NUM_PROXYURI

#=== OPTION_NUM_PROXYSCHEME

class ProxyScheme(coapOption):
    def __init__(self, scheme):
        # initialize parent
        coapOption.__init__(self, d.OPTION_NUM_PROXYSCHEME, d.OSCOAP_CLASS_U)

        # store params
        self.scheme = scheme

    def __repr__(self):
        return 'ProxyScheme(scheme={0})'.format(self.scheme)

    def getPayloadBytes(self):
        return [ord(b) for b in self.scheme]

#=== OPTION_NUM_OBJECT_SECURITY

class ObjectSecurity(coapOption):

    def __init__(self, context=None, payload=[], kid=None):

        # initialize parent
        coapOption.__init__(self, d.OPTION_NUM_OBJECT_SECURITY, d.OSCOAP_CLASS_U)

        self.context = context
        self.value = payload
        self.kid = kid

    def __repr__(self):
        return 'ObjectSecurity(context={0},payload={1}, kid={2})'.format(self.context, self.value, self.kid)

    def setValue(self, payload):
        self.value = payload

    def setKid(self,kid):
        self.kid = kid

    def setContext(self,context):
        self.context = context

    def getPayloadBytes(self):
        return self.value

# === OPTION_NUM_STATELESSPROXY

class StatelessProxy(coapOption):
    def __init__(self, value):
        # initialize parent
        coapOption.__init__(self, d.OPTION_NUM_STATELESSPROXY, d.OSCOAP_CLASS_U)

        # store params
        self.opaqueValue = value

    def __repr__(self):
        return 'StatelessProxy(value={0})'.format(self.opaqueValue)

    def getPayloadBytes(self):
        return self.opaqueValue
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
            raise e.messageFormatError('message too short, {0} bytes: no space for 1B optionDelta'.format(len(message)))
        optionDelta = u.buf2int(message[0:1])+13
        message = message[1:]
    elif optionDelta==14:
        if len(message)<2:
            raise e.messageFormatError('message too short, {0} bytes: no space for 2B optionDelta'.format(len(message)))
        optionDelta = u.buf2int(message[0:2])+269
        message = message[2:]
    else:
        raise e.messageFormatError('invalid optionDelta={0}'.format(optionDelta))
    
    log.debug('optionDelta   = {0}'.format(optionDelta))
    
    # optionLength
    if   optionLength<=12:
        pass
    elif optionLength==13:
        if len(message)<1:
            raise e.messageFormatError('message too short, {0} bytes: no space for 1B optionLength'.format(len(message)))
        optionLength = u.buf2int(message[0:1])+13
        message = message[1:]
    elif optionLength==14:
        if len(message)<2:
            raise e.messageFormatError('message too short, {0} bytes: no space for 2B optionLength'.format(len(message)))
        optionLength = u.buf2int(message[0:2])+269
        message = message[2:]
    else:
        raise e.messageFormatError('invalid optionLength={0}'.format(optionLength))
    
    log.debug('optionLength  = {0}'.format(optionLength))
    
    # optionValue
    if len(message)<optionLength:
        raise e.messageFormatError('message too short, {0} bytes: no space for optionValue'.format(len(message)))
    optionValue = message[:optionLength]
    message = message[optionLength:]
    
    log.debug('optionValue   = {0}'.format(u.formatBuf(optionValue)))
    
    #===== create option
    optionNumber = previousOptionNumber+optionDelta
    
    log.debug('optionNumber  = {0}'.format(optionNumber))
    
    if optionNumber not in d.OPTION_NUM_ALL:
        raise e.messageFormatError('invalid option number {0} (0x{0:x})'.format(optionNumber))

    if optionNumber==d.OPTION_NUM_URIHOST:
        option = UriHost(host=''.join([chr(b) for b in optionValue]))
    elif optionNumber==d.OPTION_NUM_URIPATH:
        option = UriPath(path=''.join([chr(b) for b in optionValue]))
    elif optionNumber==d.OPTION_NUM_CONTENTFORMAT:
        option = ContentFormat(cformat=optionValue)
    elif optionNumber==d.OPTION_NUM_BLOCK2:
        option = Block2(rawbytes=optionValue)
    elif optionNumber==d.OPTION_NUM_OBJECT_SECURITY:
        option = ObjectSecurity(payload=optionValue)
    elif optionNumber==d.OPTION_NUM_PROXYSCHEME:
        option = ProxyScheme(scheme=''.join([chr(b) for b in optionValue]))
    elif optionNumber==d.OPTION_NUM_STATELESSPROXY:
        option = StatelessProxy(value=optionValue)
    else:
        raise NotImplementedError('option {0} not implemented'.format(optionNumber))
    
    return (option,message)
