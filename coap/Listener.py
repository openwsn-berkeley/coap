import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('Listener')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

class Listener(object):
    
    def __init__(self,ipAddress,udpPort):
        
        # store params
        self.ipAddress  = ipAddress
        self.udpPort    = udpPort
        
        # local variables
        self.goOn       = True
    
    #======================== public ==========================================
    
    def getMessage(self):
        raise NotImplementedError()
    
    def sendMessage(self,msg):
        raise NotImplementedError()
    
    def stop(self):
        raise NotImplementedError()
    
    #======================== private =========================================