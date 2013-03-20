import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapOption')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapDefines as d
import coapUtils   as u

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
