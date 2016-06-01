import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coap')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading
import random
import traceback

import coapTokenizer    as t
import coapUtils        as u
import coapMessage      as m
import coapException    as e
import coapResource     as r
import coapDefines      as d
import coapUri
import coapTransmitter
from socketUdpDispatcher import socketUdpDispatcher
from socketUdpReal       import socketUdpReal

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
        self.transmittersLock     = threading.RLock()
        self.transmitters         = {}
        self.ackTimeout           = d.DFLT_ACK_TIMEOUT
        self.respTimeout          = d.DFLT_RESPONSE_TIMEOUT
        self.maxRetransmit        = d.DFLT_MAX_RETRANSMIT
        if testing:
            self.socketUdp        = socketUdpDispatcher(
                ipAddress         = self.ipAddress,
                udpPort           = self.udpPort,
                callback          = self._receive,
            )
        else:
            self.socketUdp        = socketUdpReal(
                ipAddress         = self.ipAddress,
                udpPort           = self.udpPort,
                callback          = self._receive,
            )

    #======================== public ==========================================

    def close(self):
        self.socketUdp.close()

    #===== client

    def GET(self,uri,confirmable=True,options=[]):
        log.debug('GET {0}'.format(uri))
        response = self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_GET,
            options     = options,
        )
        log.debug('response: {0}'.format(response))
        return response['payload']

    def PUT(self,uri,confirmable=True,options=[],payload=None):
        response = self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_PUT,
            options     = options,
            payload     = payload
        )
        log.debug('response: {0}'.format(response))
        return response['payload']

    def POST(self,uri,confirmable=True,options=[],payload=None):
        response = self._transmit(
            uri         = uri,
            confirmable = confirmable,
            code        = d.METHOD_POST,
            options     = options,
            payload     = payload
        )
        log.debug('response: {0}'.format(response))
        return response['payload']

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

    def _transmit(self,uri,confirmable,code,options=[],payload=[]):
        assert code in d.METHOD_ALL
        if code in [d.METHOD_GET,d.METHOD_DELETE]:
            assert payload==[]
        assert type(uri)==str

        (destIp,destPort,uriOptions) = coapUri.uri2options(uri)

        with self.transmittersLock:
            self._cleanupTransmitter()
            messageId        = self._getMessageID(destIp,destPort)
            token            = self._getToken(destIp,destPort)
            newTransmitter   = coapTransmitter.coapTransmitter(
                sendFunc     = self.socketUdp.sendUdp,
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
                ackTimeout   = self.ackTimeout,
                respTimeout  = self.respTimeout,
                maxRetransmit= self.maxRetransmit
            )
            key              = (destIp,destPort,token,messageId)
            assert key not in self.transmitters.keys()
            self.transmitters[key] = newTransmitter

        return newTransmitter.transmit()

    def _getMessageID(self,destIp,destPort):
        '''
        \pre transmittersLock is already acquired.
        '''
        with self.transmittersLock:
            self._cleanupTransmitter()
            found = False
            while not found:
                messageId = random.randint(0x0000,0xffff)
                alreadyUsed = False
                for (kIp,kPort,kToken,kMessageId) in self.transmitters.keys():
                    if destIp==kIp and destPort==kPort and messageId==kMessageId:
                        alreadyUsed = True
                        break
                if not alreadyUsed:
                    found = True
            return messageId

    def _getToken(self,destIp,destPort):
        '''
        \pre transmittersLock is already acquired.
        '''
        with self.transmittersLock:
            self._cleanupTransmitter()
            found = False
            while not found:
                token = random.randint(0x00,0xff)
                alreadyUsed = False
                for (kIp,kPort,kToken,kMessageId) in self.transmitters.keys():
                    if destIp==kIp and destPort==kPort and token==kToken:
                        alreadyUsed = True
                        break
                if not alreadyUsed:
                    found = True
            return token

    def _cleanupTransmitter(self):
        with self.transmittersLock:
            for (k,v) in self.transmitters.items():
                if not v.isAlive():
                    del self.transmitters[k]

    #===== receive

    def _receive(self,timestamp,sender,rawbytes):
        # all UDP packets are received here

        output  = []
        output += ['\n{0} _receive message:'.format(self.name)]
        output += ['- timestamp: {0}'.format(timestamp)]
        output += ['- sender:    {0}'.format(sender)]
        output += ['- bytes:     {0}'.format(u.formatBuf(rawbytes))]
        output  = '\n'.join(output)
        log.debug(output)

        srcIp   = sender[0]
        srcIp   = u.trimAddress(srcIp)

        srcPort = sender[1]

        # parse messages
        try:
            message = m.parseMessage(rawbytes)
        except e.messageFormatError as err:
            log.warning('malformed message {0}: {1}'.format(u.formatBuf(rawbytes),str(err)))
            return

        # dispatch message
        try:
            if   message['code'] in d.METHOD_ALL:
                # this is meant for a resource

                #==== find right resource

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

                if not resource:
                    raise e.coapRcNotFound()

                #==== get a response

                # call the right resource's method
                try:
                    if   message['code']==d.METHOD_GET:
                        (respCode,respOptions,respPayload) = resource.GET(
                            options=message['options']
                        )
                    elif message['code']==d.METHOD_POST:
                        (respCode,respOptions,respPayload) = resource.POST(
                            options=message['options'],
                            payload=message['payload']
                        )
                    elif message['code']==d.METHOD_PUT:
                        (respCode,respOptions,respPayload) = resource.PUT(
                            options=message['options'],
                            payload=message['payload']
                        )
                    elif message['code']==d.METHOD_DELETE:
                        (respCode,respOptions,respPayload) = resource.DELETE(
                            options=message['options']
                        )
                    else:
                        raise SystemError('unexpected code {0}'.format(message['code']))
                except Exception as err:
                    if isinstance(err,e.coapRc):
                        raise
                    else:
                        raise e.coapRcInternalServerError()

                #==== send back response

                # determine type of response packet
                if   message['type']==d.TYPE_CON:
                    responseType = d.TYPE_ACK
                elif message['type']==d.TYPE_NON:
                    responseType = d.TYPE_NON
                else:
                    raise SystemError('unexpected type {0}'.format(message['type']))

                # build response packets
                response = m.buildMessage(
                    msgtype             = responseType,
                    token            = message['token'],
                    code             = respCode,
                    messageId        = message['messageId'],
                    options          = respOptions,
                    payload          = respPayload,
                )

                # send
                self.socketUdp.sendUdp(
                    destIp           = srcIp,
                    destPort         = srcPort,
                    msg              = response,
                )

            elif message['code'] in d.COAP_RC_ALL:
                # this is meant for a transmitter

                # find transmitter
                msgkey = (srcIp,srcPort,message['token'],message['messageId'])

                found  = False
                with self.transmittersLock:
                    self._cleanupTransmitter()
                    for (k,v) in self.transmitters.items():
                        # try matching
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
                    raise e.coapRcBadRequest(
                        'could not find transmitter corresponding to {0}, transmitters are {1}'.format(
                            msgkey,
                            ','.join([str(k) for k in self.transmitters.keys()])
                        )
                    )

            else:
                raise NotImplementedError()

        except e.coapRc as err:

            # log
            log.warning(err)

            # determine type of response packet
            if   message['type']==d.TYPE_CON:
                responseType = d.TYPE_ACK
            elif message['type']==d.TYPE_NON:
                responseType = d.TYPE_NON
            else:
                raise SystemError('unexpected type {0}'.format(message['type']))

            # build response packets
            response = m.buildMessage(
                msgtype             = responseType,
                token            = message['token'],
                code             = err.rc,
                messageId        = message['messageId'],
            )

            # send
            self.socketUdp.sendUdp(
                destIp           = srcIp,
                destPort         = srcPort,
                msg              = response,
            )

        except Exception as err:
            log.critical(traceback.format_exc())
