import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coap')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading

import coapTokenizer    as t
import coapUtils        as u
import coapMessage      as m
import coapException    as e
import coapResource     as r
import coapDefines      as d
import coapUri
from ListenerDispatcher import ListenerDispatcher
from ListenerUdp        import ListenerUdp

class coap(object):
    
    def __init__(self,ipAddress='',udpPort=d.DEFAULT_UDP_PORT,testing=False):
        
        # store params
        self.ipAddress       = ipAddress
        self.udpPort         = udpPort
        
        # local variables
        self.name            = 'coap@[{0}]:{1}'.format(self.ipAddress,self.udpPort)
        self.resourceLock    = threading.Lock()
        self.tokenizer       = t.coapTokenizer()
        self.resources       = []
        if testing:
            self.listener    = ListenerDispatcher(
                ipAddress    = self.ipAddress,
                udpPort      = self.udpPort,
                callback     = self._messageNotification,
            )
        else:
            self.listener    = ListenerUdp(
                ipAddress    = self.ipAddress,
                udpPort      = self.udpPort,
                callback     = self._messageNotification,
            )
    
    #======================== public ==========================================
    
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
        
        # build message
        message = m.buildMessage(
            type             = type,
            token            = self.tokenizer.getNewToken(destIp,destPort),
            code             = d.METHOD_GET,
            messageId        = self.tokenizer.getNewMessageId(destIp,destPort),
            options          = options,
        )
        
        # send
        self.listener.sendMessage(
            destIp           = destIp,
            destPort         = destPort,
            msg              = message,
        )
    
    def PUT(self,uri,confirmable=True,options=[],payload=None):
        raise NotImplementedError()
    
    def POST(self,uri,confirmable=True,options=[],payload=None):
        raise NotImplementedError()
    
    def DELETE(self,uri,confirmable=True,options=[]):
        raise NotImplementedError()
    
    #===== server
    
    def addResource(self,newResource):
        assert isinstance(newResource,r.coapResource)
        
        log.debug('{0} adding resource at path="{1}"'.format(self.name,newResource.path))
        
        with self.resourceLock:
            self.resources += [newResource]
    
    #======================== private =========================================
    
    def _messageNotification(self,timestamp,sender,bytes):
        
        output  = []
        output += ['{0} got message:'.format(self.name)]
        output += ['- timestamp: {0}'.format(timestamp)]
        output += ['- sender:    {0}'.format(sender)]
        output += ['- bytes:     {0}'.format(u.formatBuf(bytes))]
        output  = '\n'.join(output)
        log.debug(output)
        
        # parse messages
        try:
            message = m.parseMessage(bytes)
        except e.messageFormatError as err:
            log.warning('malformed message {0}: {1}'.format(u.formatBuf(bytes),str(err)))
            return
        
        if   message['type']==d.TYPE_CON:
            self._handleReceivedCON(timestamp,sender,message)
        elif message['type']==d.TYPE_NON:
            self._handleReceivedNON(timestamp,sender,message)
        elif message['type']==d.TYPE_ACK:
            self._handleReceivedACK(timestamp,sender,message)
        elif message['type']==d.TYPE_RST:
            self._handleReceivedRST(timestamp,sender,message)
    
    def _handleReceivedCON(self,timestamp,sender,message):
        raise NotImplementedError()
    
    def _handleReceivedNON(self,timestamp,sender,message):
        
        (sourceIp,sourcePort) = sender
        
        # retrieve path
        path = coapUri.options2path(message['options'])
        log.debug('path="{0}"'.format(path))
        
        # find resource that matches this path
        resource = None
        with self.resourceLock:
            for r in self.resources:
                if r.matchesPath(path):
                    resource = r
                    break
        log.debug('resource={0}'.format(resource))
        
        if resource:
            try:
                if   message['code']==d.METHOD_GET:
                    returnVal = resource.GET(options=message['options'])
                elif message['code']==d.METHOD_POST:
                    returnVal = resource.GET(options=message['options'],payload=message['payload'])
                elif message['code']==d.METHOD_PUT:
                    returnVal = resource.PUT(options=message['options'],payload=message['payload'])
                elif message['code']==d.METHOD_DELETE:
                    returnVal = resource.DELETE(options=message['options'])
                else:
                    raise SystemError('unexpected code {0}'.format(message['code']))
            except e.coapRcMethodNotAllowed:
                # build message (MethodNotAllowed)
                message = m.buildMessage(
                    type          = d.TYPE_ACK,
                    token         = message['token'],
                    code          = d.COAP_RC_4_05_METHODNOTALLOWED,
                    messageId     = message['messageId'],
                )
        else:
            # build message (NotFound)
            message = m.buildMessage(
                type              = d.TYPE_ACK,
                token             = message['token'],
                code              = d.COAP_RC_4_04_NOTFOUND,
                messageId         = message['messageId'],
            )
        
        # build message (success)
        message = m.buildMessage(
            type                  = d.TYPE_ACK,
            token                 = message['token'],
            code                  = d.COAP_RC_2_05_CONTENT,
            messageId             = message['messageId'],
            payload               = returnVal
        )
        
        # send
        self.listener.sendMessage(
            destIp           = sourceIp,
            destPort         = sourcePort,
            msg              = message,
        )
    
    def _handleReceivedACK(self,timestamp,sender,message):
        raise NotImplementedError()
    
    def _handleReceivedRST(self,timestamp,sender,message):
        raise NotImplementedError()