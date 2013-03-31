import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('socketUdpDispatcher')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import time
import threading

from pydispatch import dispatcher

import socketUdp
import coapUtils as u

class socketUdpDispatcher(socketUdp.socketUdp):
    
    def __init__(self,ipAddress,udpPort,callback):
        
        # log
        log.debug('creating instance')
        
        # initialize the parent class
        socketUdp.socketUdp.__init__(self,ipAddress,udpPort,callback)
        
        # change name
        self.name       = 'socketUdpDispatcher@{0}:{1}'.format(self.ipAddress,self.udpPort)
        self.gotMsgSem  = threading.Semaphore()
        
        # connect to dispatcher
        dispatcher.connect(
            receiver = self._messageNotification,
            signal   = (self.ipAddress,self.udpPort),
        )
        
        # start myself
        self.start()
    
    #======================== public ==========================================
    
    def sendUdp(self,destIp,destPort,msg):
        
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
            receiver = self._messageNotification,
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
        log.debug("got {2} from {1} at {0}".format(timestamp,sender,u.formatBuf(data)))
        
        # call the callback
        self.callback(timestamp,sender,data)
        
        # update stats
        self._incrementRx()
        
        # release the lock
        self.gotMsgSem.release()
    
    def run(self):
        while self.goOn:
            self.gotMsgSem.acquire()