import threading

import coapDefines as defines

class coap(object):
    
    def __init__(udpPort=defines.DEFAULT_UDP_PORT):
        
        # store params
        self.udpPort    = udpPort
        
        # local variables
        self.dataLock   = threading.Lock()
        self.resources  = []
    
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
    
    def addResource():
        raise NotImplementedError()
    
    def startServer():
        raise NotImplementedError()
    
    def stopServer():
        raise NotImplementedError()
    
    #======================== private ===============================
    