import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coap')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading

import coapResource
import coapOption
import coapDefines as d
import coapUri
from ListenerDispatcher import ListenerDispatcher
from ListenerUdp        import ListenerUdp

class coap(object):
    
    def __init__(self,ipAddress='',udpPort=d.DEFAULT_UDP_PORT,testing=False):
        
        # store params
        self.ipAddress      = ipAddress
        self.udpPort        = udpPort
        
        # local variables
        self.resourceLock   = threading.Lock()
        self.tokenizer      = coapTokenizer.coapTokenizer()
        self.resources      = []
        if testing:
            self.listener   = ListenerDispatcher(
                ipAddress   = self.ipAddress,
                udpPort     = self.udpPort,
                callback    = self._messageNotification,
            )
        else:
            self.listener   = ListenerUdp(
                ipAddress   = self.ipAddress,
                udpPort     = self.udpPort,
                callback    = self._messageNotification,
            )
    
    #======================== public ================================
    
    def close(self):
        self.listener.close()
    
    #===== client
    
    def GET(self,uri,confirmable=True,options=[]):
        
        (destIp,destPort,uriOptions) = coapUri.uri2options(uri)
        
        # add URI options
        options += uriOptions
        
        # determine message type
        if confirmable:
            type = d.TYPE_CON
        else:
            type = d.TYPE_NON
        
        # get a new token
        token           = 
        
        # build message
        message = coapMessage.buildMessage(
            type        = type,
            token       = self.tokenizer.getNewToken(destIp,destPort),
            code        = d.METHOD_GET,
            messageId   = self.tokenizer.getNewMessageId(destIp,destPort),
            options     = options,
        )
        
        raise NotImplementedError()
    
    def PUT(self,uri,confirmable=True,options=[],payload=None):
        raise NotImplementedError()
    
    def POST(self,uri,confirmable=True,options=[],payload=None):
        raise NotImplementedError()
    
    def DELETE(self,uri,confirmable=True,options=[]):
        raise NotImplementedError()
    
    #===== server
    
    def addResource(self,newResource):
        assert isinstance(newResource,coapResource.coapResource)
        
        with self.resourceLock:
            self.resources += [newResource]
    
    #======================== private ===============================
    
    def _messageNotification(self,timestamp,sender,data):
        pass
    