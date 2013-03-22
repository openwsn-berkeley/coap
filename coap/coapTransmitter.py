import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapTransmitter')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading

class coapTransmitter(threading.Thread):
    '''
    \brief A class which takes care of transmitting a data packet.
    
    It handles:
    - waiting for an app-level reply 
    - waiting for a transport-level ACK in case of a confirmable messages.
    
    The thread is ephemeral: it is created for each transmission, and returns
    when the transmission is completed, or timed out.
    '''
    
    STATE_INIT                    = 'INIT'
    STATE_TXCON                   = 'TXCON'
    STATE_TXNON                   = 'TXNON'
    STATE_WAITFORACK              = 'WAITFORACK'
    STATE_WAITFORRESPCON          = 'WAITFORRESPCON'
    STATE_WAITFORRESPNON          = 'WAITFORRESPNON'
    STATE_WAITFOREXPIRATIONMID    = 'WAITFOREXPIRATIONMID'
    STATE_ALL = [
        STATE_INIT,
        STATE_TXCON,
        STATE_TXNON,
        STATE_WAITFORACK,
        STATE_WAITFORRESPCON,
        STATE_WAITFORRESPNON,
        STATE_WAITFOREXPIRATIONMID,
    ]
    
    def __init__(self,srcIp,srcPort,destIp,destPort,confirmable,messageId,code,token,options,payload):
         
        # store params
        self.srcIp           = srcIp
        self.srcPort         = srcPort
        self.destIp          = destIp
        self.destPort        = destPort
        self.confirmable     = confirmable
        self.messageId       = messageId
        self.code            = code
        self.token           = token
        self.options         = options
        self.payload         = payload
        
        # local variables
        self.stateLock       = Lock()
        self.state           = self.STATE_INIT
        
        # initialize parent
        threading.Thread.__init__(self)
        
        # give this thread a name
        self.name            = '[{0}]:{1}--m{2:x},t{3:x}-->[{2}]:{3}'.format(
            self.srcIp,
            self.srcPort,
            self.messageId,
            self.token,
            self.destIp,
            self.destPort,
        )
        
        # start myself
        self.start()
    
    def run():
        raise NotImplementedError()
    
    #======================== public ==========================================
    
    def transmit(self):
        '''
        \brief Start the interaction with the destination, including waiting
            for transport-level ACK and app-level response.
            
        This function blocks until a response is received.
        
        \raise coapTimeoutAck      When no ACK is received in time.
        \raise coapTimeoutResponse When no response is received.
        
        \return The received response.
        '''
        
        #==== transmit request
        
        # determine message type
        if confirmable:
            type = d.TYPE_CON
        else:
            type = d.TYPE_NON
        
        # build message
        message = m.buildMessage(
            type             = type,
            token            = self.tokenizer.getNewToken(destIp,destPort),
            code             = code,
            messageId        = self.tokenizer.getNewMessageId(destIp,destPort),
            options          = options,
        )
        
        # send
        self.listener.sendMessage(
            destIp           = destIp,
            destPort         = destPort,
            msg              = message,
        )
        
        #==== wait for request ACK
        
        raise NotImplementedError()
        
        #==== wait for response
        
        raise NotImplementedError()
        
        #==== transmit reponse ACK
        
        raise NotImplementedError()
        
        #==== arm messageID expiration
        
        raise NotImplementedError()
    
    def getState(self):
        with self.stateLock:
            returnVal = self.state
        return returnVal
    
    #======================= private ==========================================
    
    def _changeState(self,newState):
        with self.stateLock:
            self.state = newState
        log.debug('{0}: state={0}'.format(self.name,newState))