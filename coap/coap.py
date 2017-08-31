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
import socket

import coapTokenizer        as t
import coapUtils            as u
import coapMessage          as m
import coapException        as e
import coapResource         as r
import coapDefines          as d
import coapOption           as o
import coapObjectSecurity   as oscoap
import coapUri
import coapTransmitter
from socketUdpDispatcher import socketUdpDispatcher
from socketUdpReal       import socketUdpReal

class coap(object):

    def __init__(self,ipAddress='',udpPort=d.DEFAULT_UDP_PORT,testing=False,receiveCallback=None):

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
        self.secContextHandler    = None
        if receiveCallback:
            callback = receiveCallback
        else:
            callback = self._receive
        if testing:
            self.socketUdp        = socketUdpDispatcher(
                ipAddress         = self.ipAddress,
                udpPort           = self.udpPort,
                callback          = callback,
            )
        else:
            self.socketUdp        = socketUdpReal(
                ipAddress         = self.ipAddress,
                udpPort           = self.udpPort,
                callback          = callback,
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

    def addSecurityContextHandler(self, cb):
        self.secContextHandler = cb

    #======================== private =========================================

    #===== transmit

    def _transmit(self,uri,confirmable,code,options=[],payload=[]):
        assert code in d.METHOD_ALL
        if code in [d.METHOD_GET,d.METHOD_DELETE]:
            assert payload==[]
        assert type(uri)==str

        (host,destPort,uriOptions) = coapUri.uri2options(uri)
        destIp = socket.getaddrinfo(host, destPort)[0][4][0]
        (securityContext, sequenceNumber) = oscoap.getRequestSecurityParams(oscoap.objectSecurityOptionLookUp(options))

        with self.transmittersLock:
            self._cleanupTransmitter()
            messageId           = self._getMessageID(destIp,destPort)
            token               = self._getToken(destIp,destPort)
            newTransmitter      = coapTransmitter.coapTransmitter(
                sendFunc        = self.socketUdp.sendUdp,
                srcIp           = self.ipAddress,
                srcPort         = self.udpPort,
                destIp          = destIp,
                destPort        = destPort,
                confirmable     = confirmable,
                messageId       = messageId,
                code            = code,
                token           = token,
                options         = uriOptions+options,
                payload         = payload,
                securityContext = securityContext,
                requestSeq      = sequenceNumber,
                ackTimeout      = self.ackTimeout,
                respTimeout     = self.respTimeout,
                maxRetransmit   = self.maxRetransmit
            )
            key              = (destIp,destPort,token,messageId)
            assert key not in self.transmitters.keys()
            self.transmitters[key] = newTransmitter

        response = newTransmitter.transmit()

        if securityContext:
            try:
                (innerOptions, plaintext) = oscoap.unprotectMessage(securityContext,
                                                                    version=response['version'],
                                                                    code=response['code'],
                                                                    options=response['options'],
                                                                    ciphertext=response['ciphertext'],
                                                                    partialIV=sequenceNumber,
                                                                    )
                response['options'] = response['options'] + innerOptions
                response['payload'] = plaintext
            except e.oscoapError:
                raise

        return response

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
            options = message['options']
        except e.messageFormatError as err:
            log.warning('malformed message {0}: {1}'.format(u.formatBuf(rawbytes),str(err)))
            return

        # dispatch message
        try:
            if   message['code'] in d.METHOD_ALL:
                # this is meant for a resource (request)

                #==== decrypt message if encrypted
                innerOptions = []
                foundContext = None
                requestPartialIV = None
                if 'ciphertext' in message.keys():
                    # retrieve security context
                    # before decrypting we don't know what resource this request is meant for
                    # so we take the first binding with the correct context (recipientID)
                    blindContext = self._securityContextLookup(u.buf2str(message['kid']))

                    if not blindContext:
                        if self.secContextHandler:
                            appContext = self.secContextHandler(u.buf2str(message['kid']))
                            if not appContext:
                                raise e.coapRcUnauthorized('Security context not found.')
                        else:
                            raise e.coapRcUnauthorized('Security context not found.')

                    foundContext = blindContext if blindContext != None else appContext

                    requestPartialIV = u.zeroPadString(u.buf2str(message['partialIV']), foundContext.getIVLength())

                    # decrypt the message
                    try:
                        (innerOptions, plaintext) = oscoap.unprotectMessage(foundContext,
                                                                          version=message['version'],
                                                                          code=message['code'],
                                                                          options=message['options'],
                                                                          ciphertext=message['ciphertext'],
                                                                          partialIV=requestPartialIV
                                                                            )
                    except e.oscoapError as err:
                        raise e.coapRcBadRequest('OSCOAP unprotect failed: {0}'.format(str(err)))

                    payload = plaintext
                else: # message not encrypted
                    payload = message['payload']

                options += innerOptions

                #==== find right resource

                # retrieve path
                path = coapUri.options2path(options)
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

                #==== check if appropriate security context was used for the resource
                (context, authorizedMethods) = resource.getSecurityBinding()

                if context is not None:
                    if context != foundContext:
                        raise e.coapRcUnauthorized('Unauthorized security context for the given resource')

                objectSecurity = oscoap.objectSecurityOptionLookUp(options)
                if objectSecurity:
                    objectSecurity.setContext(foundContext)
                #==== get a response

                # call the right resource's method
                try:
                    if   message['code']==d.METHOD_GET and d.METHOD_GET in authorizedMethods:
                        (respCode,respOptions,respPayload) = resource.GET(
                            options=options
                        )
                    elif message['code']==d.METHOD_POST and d.METHOD_POST in authorizedMethods:
                        (respCode,respOptions,respPayload) = resource.POST(
                            options=options,
                            payload=payload
                        )
                    elif message['code']==d.METHOD_PUT and d.METHOD_PUT in authorizedMethods:
                        (respCode,respOptions,respPayload) = resource.PUT(
                            options=options,
                            payload=payload
                        )
                    elif message['code']==d.METHOD_DELETE and d.METHOD_DELETE in authorizedMethods:
                        (respCode,respOptions,respPayload) = resource.DELETE(
                            options=options
                        )
                    elif message['code'] not in d.METHOD_ALL:
                        raise SystemError('unexpected code {0}'.format(message['code']))
                    else:
                        raise e.coapRcUnauthorized('Unauthorized method for the given resource')
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

                # if resource is protected with a security context, add Object-Security option
                if foundContext:
                    # verify that the Object-Security option was not set by the resource handler
                    assert not any(isinstance(option, o.ObjectSecurity) for option in respOptions)
                    objectSecurity = o.ObjectSecurity(context=foundContext)
                    respOptions += [objectSecurity]

                # if Stateless-Proxy option was present in the request echo it
                for option in options:
                    if isinstance(option, o.StatelessProxy):
                        respOptions += [option]
                        break

                # build response packets and pass partialIV from the request for OSCOAP's processing
                response = m.buildMessage(
                    msgtype          = responseType,
                    token            = message['token'],
                    code             = respCode,
                    messageId        = message['messageId'],
                    options          = respOptions,
                    payload          = respPayload,
                    securityContext  = foundContext,
                    partialIV        = requestPartialIV
                )

                # send
                self.socketUdp.sendUdp(
                    destIp           = srcIp,
                    destPort         = srcPort,
                    msg              = response,
                )

            elif message['code'] in d.COAP_RC_ALL:
                # this is meant for a transmitter (response)

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

            # if Stateless-Proxy option was present in the request echo it
            errorOptions = []
            for option in options:
                if isinstance(option, o.StatelessProxy):
                    errorOptions += [option]
                    break

            # build response packets
            response = m.buildMessage(
                msgtype             = responseType,
                token            = message['token'],
                code             = err.rc,
                messageId        = message['messageId'],
                options          = errorOptions,
            )

            # send
            self.socketUdp.sendUdp(
                destIp           = srcIp,
                destPort         = srcPort,
                msg              = response,
            )

        except Exception as err:
            log.critical(traceback.format_exc())

    def _securityContextLookup(self, keyID):
        with self.resourceLock:
            for r in self.resources:
                (ctx, authzMethods) = r.getSecurityBinding()
                if ctx:
                    if keyID == ctx.recipientID:
                        return ctx
            return None
