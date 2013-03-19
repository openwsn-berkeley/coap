import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coap')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading

import coapDefines as defines
from ListenerDispatcher import ListenerDispatcher
from ListenerUdp        import ListenerUdp

class coap(object):
    
    def __init__(self,ipAddress='',udpPort=defines.DEFAULT_UDP_PORT,testing=False):
        
        # store params
        self.ipAddress      = ipAddress
        self.udpPort        = udpPort
        
        # local variables
        self.dataLock       = threading.Lock()
        self.resources      = []
        if testing:
            self.listener   = ListenerDispatcher(self.ipAddress,self.udpPort)
        else:
            self.listener   = ListenerUdp(self.ipAddress,self.udpPort)
    
    #======================== public ================================
    
    #===== client
    
    def GET(uri,confirmable=True,options=[]):
        raise NotImplementedError()
    
    def PUT(uri,confirmable=True,options=[],payload=None):
        raise NotImplementedError()
    
    def POST(uri,confirmable=True,options=[],payload=None):
        raise NotImplementedError()
    
    def DELETE(uri,confirmable=True,options=[]):
        raise NotImplementedError()
    
    #===== server
    
    def addResource(newResource):
        assert isinstance(newResource,coapResource)
        raise NotImplementedError()
    
    #======================== private ===============================
    