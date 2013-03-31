import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('socketUdp')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading

class socketUdp(threading.Thread):
    
    def __init__(self,ipAddress,udpPort,callback):
        
        # store params
        self.ipAddress  = ipAddress
        self.udpPort    = udpPort
        self.callback   = callback
        
        # local variables
        self.goOn       = True
        self.statsLock  = threading.Lock()
        self.resetStats()
        
        # initialize the parent
        threading.Thread.__init__(self)
        
        # give this thread a name
        self.name       = 'socketUdp'
    
    #======================== virtual methods =================================
    
    def sendUdp(self,destIp,destPort,msg):
        raise NotImplementedError() # abstract method
    
    def close(self):
        raise NotImplementedError() # abstract method
    
    def resetStats(self):
        with self.statsLock:
            self.stats = {
                'numTx': 0,
                'numRx': 0,
            }
    
    def getStats(self):
        with self.statsLock:
            return self.stats.copy()
    
    #======================== private =========================================
    
    def _incrementTx(self):
        with self.statsLock:
            self.stats['numTx']+=1
    
    def _incrementRx(self):
        with self.statsLock:
            self.stats['numRx']+=1