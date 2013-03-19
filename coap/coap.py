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
import coapDefines
import coapException as e
from ListenerDispatcher import ListenerDispatcher
from ListenerUdp        import ListenerUdp

class coap(object):
    
    def __init__(self,ipAddress='',udpPort=coapDefines.DEFAULT_UDP_PORT,testing=False):
        
        # store params
        self.ipAddress      = ipAddress
        self.udpPort        = udpPort
        
        # local variables
        self.resourceLock   = threading.Lock()
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
        
        # add URI to options
        options += self._uri2options(uri)
        
        # build message
        message = self.buildMessages(options,confirmable)
        
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
    
    @classmethod
    def _uri2options(self,uri):
        
        options = []
        
        # scheme
        if not uri.startswith(coapDefines.COAP_SCHEME):
            raise e.coapMalformattedUri('does not start with {0}'.format(coapDefines.COAP_SCHEME))
        uri = uri.split(coapDefines.COAP_SCHEME,1)[1]
        
        # ip address and port
        ipPort = uri.split('/')[0]
        temp   = ipPort.split(':')
        if   len(temp)==1:
            ip   = temp[0]
            port = coapDefines.DEFAULT_UDP_PORT
        elif len(temp)==2:
            ip   = temp[0]
            try:
                port = int(temp[1])
            except ValueError:
                e.coapMalformattedUri('invalud port'.format(temp[1]))
        else:
            raise e.coapMalformattedUri('invalud ip address and port'.format(temp))
        uri = uri.split(ipPort,1)[1]
        
        # TODO: use DNS to resolve name into IP and add Uri-host option
        
        # Uri-path
        paths = uri.split('&')[0].split('/')
        for p in paths:
            options += [coapOption.UriPath(p)]
        
        # Uri-query
        # TODO
        
        return (ip,port,options)