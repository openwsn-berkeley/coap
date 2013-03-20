import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapTokenizer')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading
import random

class coapTokenizer(object):
    
    def __init__(self):
        
        # local params
        self.dataLock   = threading.Lock()
        self.tokens     = {}
    
    #======================== public ==========================================
    
    def getNewMessageId(self,ip,port):
        
        # TODO: implement real token management
        
        return random.randint(0x0000,0xffff)
    
    def getNewToken(self,ip,port):
        
        # TODO: implement real token management
        
        return random.randint(0x00,0xff)