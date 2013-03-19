import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('ListenerDispatcher')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import socket
import time
import threading

from pydispatch import dispatcher

import Listener

class ListenerDispatcher(Listener.Listener):
    
    def __init__(self,ipAddress,udpPort):
        # log
        log.debug('creating instance')
        
        # initialize the parent class
        Listener.Listener.__init__(self,ipAddress,udpPort)
        
        # local variables
        self.dispatcherLock = threading.Lock()
        
        # connect to dispatcher
        dispatcher.connect(
            receiver = self.getMessage,
            signal   = (self.ipAddress,self.udpPort),
        )
    
    #======================== public ==========================================
    
    def getMessage(self,signal,sender,data):
        
        timestamp = time.time()
        
        log.debug("got {2} from {1} at {0}".format(timestamp,sender,data))
        
        return (timestamp,sender,data)
    
    def sendMessage(self,destIp,destPort,msg):
        
        # send over dispatcher
        dispatcher.send(
            signal = (destIp,destPort),
            sender = (self.ipAddress,self.udpPort),
            data   = msg
        )
        
        with self.socketLock:
            self.socket_handler.sendto(msg,(destIp,destPort))
    
    def stop(self):
        # disconnect from dispatcher
        dispatcher.disconnect(
            receiver = self.getMessage,
            signal   = (self.ipAddress,self.udpPort),
        )
    
    #======================== private =========================================