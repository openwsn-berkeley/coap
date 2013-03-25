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
        self.ipAddress            = ipAddress
        self.udpPort              = udpPort
        
        # local variables
        self.name                 = 'coap@[{0}]:{1}'.format(self.ipAddress,self.udpPort)
        self.resourceLock         = threading.Lock()
        self.tokenizer            = t.coapTokenizer()
        self.resources            = []
        self.transmittersLock     = threading.Lock()
        self.transmitters         = {}
        if testing:
            self.listener         = ListenerDispatcher(
                ipAddress         = self.ipAddress,
                udpPort           = self.udpPort,
                callback          = self._receive,
            )
        else:
            self.listener         = ListenerUdp(
                ipAddress         = self.ipAddress,
                udpPort           = self.udpPort,
                callback          = self._receive,
            )
    
    #======================== public ==========================================
    
    def close(self):
        self.listener.close()
    
    #===== client
    
    def GET(self,uri,confirmable=True,options=[]):
        self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_GET,
            options     = options,
        )
    
    def PUT(self,uri,confirmable=True,options=[],payload=None):
        self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_PUT,
            options     = options,
            payload     = payload
        )
    
    def POST(self,uri,confirmable=True,options=[],payload=None):
        self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_POST,
            options     = options,
            payload     = payload
        )
    
    def DELETE(self,uri,confirmable=True,options=[]):
        self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_DELETE,
            options     = options,
        )
    
    #===== server
    
    def addResource(self,newResource):
        assert isinstance(newResource,r.coapResource)
        
        log.debug('{0} adding resource at path="{1}"'.format(self.name,newResource.path))
        
        with self.resourceLock:
            self.resources += [newResource]
    
    #======================== private =========================================
    
    #===== transmit
    
    def _transmit(self,uri,confirmable,code,options=[],payload=None):
        assert code in d.METHOD_ALL
        if code in [d.METHOD_GET,d.METHOD_DELETE]:
            assert payload==None
        assert type(uri)==str
        
        (destIp,destPort,uriOptions) = coapUri.uri2options(uri)
        
        with self.transmittersLock:
            messageId        = self._getMessageID(destIp,destPort)
            token            = self._getToken(destIp,destPort)
            newTransmitter   = coapTransmitter(
                srcIp        = self.ipAddress,    
                srcPort      = self.udpPort,
                destIp       = destIp,
                destPort     = destPort,
                confirmable  = confirmable,
                messageId    = messageId,
                code         = code,
                token        = token,
                options      = uriOptions+options,
                payload      = payload,
            )
            key              = (destIp,destPort,token,messageId)
            assert key not in self.transmitters.keys()
            self.transmitters[key] = newTransmitter
        
        return newTransmitter.transmit()
    
    def _getMessageID(self,destIp,destPort):
        '''
        \pre transmittersLock is already acquired.
        '''
        raise NotImplementedError()
    
    def _getToken(self,destIp,destPort):
        '''
        \pre transmittersLock is already acquired.
        '''
        raise NotImplementedError()
    
    #===== receive
        
    def _receive(self,timestamp,sender,bytes):
        
        output  = []
        output += ['{0} got message:'.format(self.name)]
        output += ['- timestamp: {0}'.format(timestamp)]
        output += ['- sender:    {0}'.format(sender)]
        output += ['- bytes:     {0}'.format(u.formatBuf(bytes))]
        output  = '\n'.join(output)
        log.debug(output)
        
        srcIp   = sender[0]
        srcPort = sender[1]
        
        # parse messages
        try:
            message = m.parseMessage(bytes)
        except e.messageFormatError as err:
            log.warning('malformed message {0}: {1}'.format(u.formatBuf(bytes),str(err)))
            return
        
        try:
            msgkey = (srcIp,srcPort,message['token'],message['messageId'])
            found  = False
            with self.transmittersLock:
                for (k,v) in self.transmitters:
                    # delete dead transmitters
                    if not v.isAlive():
                        del self.transmitters[k]
                    
                    if (
                            msgkey[0]==k[0] and
                            msgkey[1]==k[1] and
                            (
                                msgkey[2]==k[2] or
                                msgkey[3]==k[3]
                            )
                        ):
                        found = True
                        v.receiveMessage(timestamp,srcIp,srcPort,message)
                        break
            if found==False:
                raise e.coapRcBadRequest()
        except e.coapRc:
            raise NotImplementedError()
        
        if   message['type']==d.TYPE_CON:
            self._receiveCON(timestamp,sender,message)
        elif message['type']==d.TYPE_NON:
            self._receiveNON(timestamp,sender,message)
        elif message['type']==d.TYPE_ACK:
            self._receiveACK(timestamp,sender,message)
        elif message['type']==d.TYPE_RST:
            self._receiveRST(timestamp,sender,message)
    
    def _receiveCON(self,timestamp,sender,message):
        raise NotImplementedError()
    
    def _receiveNON(self,timestamp,sender,message):
        
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
    
    def _receiveACK(self,timestamp,sender,message):
        raise NotImplementedError()
    
    def _receiveRST(self,timestamp,sender,message):
        raise NotImplementedError()