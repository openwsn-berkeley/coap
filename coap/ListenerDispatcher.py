import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('ListenerDispatcher')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import time
import threading

from pydispatch import dispatcher

import Listener

class ListenerDispatcher(Listener.Listener):
    
    def __init__(self,ipAddress,udpPort,callback):
        
        # log
        log.debug('creating instance')
        
        # initialize the parent class
        Listener.Listener.__init__(self,ipAddress,udpPort,callback)
        
        # change name
        self.name       = 'ListenerDispatcher@{0}:{1}'.format(self.ipAddress,self.udpPort)
        self.gotMsgSem  = threading.Semaphore()
        
        # connect to dispatcher
        dispatcher.connect(
            receiver = self._messageNotification,
            signal   = (self.ipAddress,self.udpPort),
        )
        
        # start myself
        self.start()
    
    #======================== public ==========================================
    
    def sendMessage(self,destIp,destPort,msg):
        
        # send over dispatcher
        dispatcher.send(
            signal = (destIp,destPort),
            sender = (self.ipAddress,self.udpPort),
            data   = msg
        )
        
        # update stats
        self._incrementTx()
    
    def close(self):
        # disconnect from dispatcher
        dispatcher.disconnect(
            receiver = self.getMessage,
            signal   = (self.ipAddress,self.udpPort),
        )
        
        # stop
        self.goOn    = False
        self.gotMsgSem.release()
    
    #======================== private =========================================
    
    def _messageNotification(self,signal,sender,data):
        
        # get reception time
        timestamp = time.time()
        
        # log
        log.debug("got {2} from {1} at {0}".format(timestamp,sender,data))
        
        # call the callback
        self.callback(timestamp,sender,data)
        
        # update stats
        self._incrementRx()
        
        # release the lock
        self.gotMsgSem.release()
    
    def run(self):
        while self.goOn:
            self.gotMsgSem.acquire()