import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapTransmitter')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import time
import threading
import random

import coapDefines          as d
import coapException        as e
import coapUtils            as u
import coapMessage          as m

class coapTransmitter(threading.Thread):
    '''
    \brief A class which takes care of transmitting a CoAP message.

    It handles:
    - waiting for an app-level reply, and
    - waiting for a transport-level ACK in case of a confirmable messages.

    The thread is ephemeral: it is created for each transmission, and becomes
    inactive when the transmission is completed, or times out.
    '''

    # states of the finite state machine this class implements
    STATE_INIT                    = 'INIT'
    STATE_TXCON                   = 'TXCON'
    STATE_TXNON                   = 'TXNON'
    STATE_WAITFORACK              = 'WAITFORACK'
    STATE_ACKRX                   = 'ACKRX'
    STATE_WAITFOREXPIRATIONMID    = 'WAITFOREXPIRATIONMID'
    STATE_WAITFORRESP             = 'WAITFORRESP'
    STATE_RESPRX                  = 'RESPRX'
    STATE_TXACK                   = 'TXACK'
    STATE_ALL = [
        STATE_INIT,
        STATE_TXCON,
        STATE_TXNON,
        STATE_WAITFORACK,
        STATE_WAITFOREXPIRATIONMID,
        STATE_WAITFORRESP,
        STATE_TXACK,
    ]

    def __init__(self,sendFunc,srcIp,srcPort,destIp,destPort,confirmable,messageId,code,token,options,payload,securityContext,requestSeq,ackTimeout,respTimeout,maxRetransmit):
        '''
        \brief Initilizer function.

        This function initializes this instance by recording everything about
        the CoAP message to be exchange with the remote endpoint. It does not,
        however, initiate the exchange, which is done by calling the transmit()
        method.

        \paran[in] sendFunc The function to call to send a CoAP message.
        \param[in] srcIp    The IP address of the local endpoint, a string of the
            form 'aaaa::1'.
        \param[in] srcport  The UDP port the local endpoint is attached to, an
            integer between 0x0000 and 0xffff.
        \param[in] destIp   The IP address of the remote CoAP endpoint, a
            string of the form 'aaaa::1'.
        \param[in] destPort The UDP port the remote endpoint is attached to, an
            integer between 0x0000 and 0xffff.
        \param[in] confirmable A boolean indicating whether the CoAP request is
            to be send confirmable (True) or non-confirmable (False).
        \param[in] messageId The message ID to be used for the CoAP request, an
            integer. The caller of this function needs to enforce unicity rules
            for the value passed.
        \param[in] code     The CoAP method to used in the request. Needs to a
            value of METHOD_ALL.
        \param[in] token    The token to be used for this exchange. The caller
            of this function needs to enforce unicity rules for the value
            passed.
        \param[in] options  A list of CoAP options. Each element needs to be
            an instance of the coapOption class. Note that this class will add
            appropriate CoAP options to encore the URI and query, if needed.
        \param[in] payload  The payload to pass in the CoAP request. This needs
            to be a byte list, i.e. a list of intergers between 0x00 and 0xff.
            This function does not parse this payload, which is written as-is
            in the CoAP request.
        \param[in] securityContext Security context used for protection of the request
        \param[in] requestSeq OSCOAP's sequence number from the request.
        \param[in] ackTimeout The ACK timeout.
        \param[in] respTimeout The app-level response timeout.
        '''

        # log
        log.debug('creating instance')

        # store params
        self.sendFunc        = sendFunc
        self.srcIp           = srcIp
        self.srcPort         = srcPort
        self.destIp          = destIp
        self.destPort        = destPort
        self.confirmable     = confirmable
        self.messageId       = messageId
        self.code            = code
        self.token           = token
        self.options         = options
        self.payload         = payload
        self.securityContext = securityContext
        self.requestSeq      = requestSeq
        self.maxRetransmit   = maxRetransmit

        # local variables
        self.dataLock        = threading.Lock()  # lock access to internal state
        self.fsmSem          = threading.Lock()  # trigger an FSM iteration
        self.startLock       = threading.Lock()  # released to start communicating
        self.endLock         = threading.Lock()  # released when done communicating
        self.stateLock       = threading.RLock() # busy setting or getting FSM state
        self.rxMsgEvent      = threading.Event()
        self.receivedACK     = None
        self.receivedResp    = None
        self.coapResponse    = None
        self.coapError       = None
        self.state           = self.STATE_INIT   # current state of the FSM
        self.numTxCON        = 0
        self.ackTimeout      = ackTimeout
        self.respTimeout     = respTimeout
        self.fsmGoOn         = True
        self.fsmAction       = {
            self.STATE_INIT:                     self._action_INIT,
            self.STATE_TXCON:                    self._action_TXCON,
            self.STATE_TXNON:                    self._action_TXNON,
            self.STATE_WAITFORACK:               self._action_WAITFORACK,
            self.STATE_ACKRX:                    self._action_ACKRX,
            self.STATE_WAITFOREXPIRATIONMID:     self._action_WAITFOREXPIRATIONMID,
            self.STATE_WAITFORRESP:              self._action_WAITFORRESP,
            self.STATE_RESPRX:                   self._action_RESPRX,
            self.STATE_TXACK:                    self._action_TXACK,
        }

        # initialize parent
        threading.Thread.__init__(self)

        # give this thread a name
        self.name            = '[{0}]:{1}--m0x{2:x},0x{3:x}-->[{4}]:{5}'.format(
            self.srcIp,
            self.srcPort,
            self.messageId,
            self.token,
            self.destIp,
            self.destPort,
        )

        # by default, I'm not communicating
        self.startLock.acquire()
        self.endLock.acquire()

        # start the thread's execution
        self.start()

    #======================== public ==========================================

    def transmit(self):
        '''
        \brief Start the interaction with the destination, including waiting
            for transport-level ACK (if needed), waiting for an app-level
            response, and ACKing that (if needed)

        This function blocks until a response is received, or the interaction
        times out.

        \raise coapTimeout      When either no ACK is received in time (for
           confirmable requests), or no application-level response is received.

        \return The received response, already parsed.
        '''

        # log
        log.debug('transmit()')

        # start the thread's execution
        self.startLock.release()

        # wait for it to be done
        self.endLock.acquire()

        # raise an exception if went wrong, or return response
        with self.dataLock:
            if self.coapError:
                assert not self.coapResponse
                raise self.coapError #pylint: disable=E0702
            if self.coapResponse:
                assert not self.coapError
                return self.coapResponse

        raise SystemError('neither an error, nor a response')

    def getState(self):
        with self.stateLock:
            return self.state

    def receiveMessage(self, timestamp, srcIp, srcPort, message):
        assert srcIp==self.destIp
        assert srcPort==self.destPort
        assert (message['token']==self.token) or (message['messageId']==self.messageId)

        # log
        log.debug('receiveMessage timestamp={0} srcIp={1} srcPort={2} message={3}'.format(timestamp,srcIp,srcPort,message))

        # turn message into exception if needed
        if message['code'] not in d.METHOD_ALL+d.COAP_RC_ALL_SUCCESS:
            message = e.coapRcFactory(message['code'])

        # store packet
        with self.dataLock:
            self.LastRxPacket = (timestamp,srcIp,srcPort,message)

        # signal reception
        self.rxMsgEvent.set()

    #======================= private ==========================================

    #===== fsm

    def run(self):

        try:
            # wait for transmit() to be called
            self.startLock.acquire()

            # log
            log.debug('start FSM')

            while self.fsmGoOn:
                # wait for the FSM to be kicked
                self.fsmSem.acquire()

                # log
                log.debug('fsm state iteration: {0}'.format(self.getState()))

                # call the appropriate action
                self.fsmAction[self.getState()]()

                # is interaction done?
                with self.dataLock:
                    if self.coapError or self.coapResponse:
                        self.endLock.release()
                        self.fsmGoOn=False
        except Exception as err:
            log.critical(u.formatCrashMessage(
                    threadName = self.name,
                    error      = err
                )
            )

    def _action_INIT(self):

        # log
        log.debug('_action_INIT()')

        # set state according to confirmable
        if self.confirmable:
            self._setState(self.STATE_TXCON)
        else:
            self._setState(self.STATE_TXNON)

        # kick FSM
        self._kickFsm()

    def _action_TXCON(self):

        # log
        log.debug('_action_TXCON()')

        # flag error if max number of CON transmits reached
        if self.numTxCON>self.maxRetransmit+1:
            # this is an error case
            self.coapError   = e.coapTimeout('No ACK received after {0} tries (max {1})'.format(
                    self.numTxCON,
                    self.maxRetransmit+1,
                )
            )
            return

        # build message
        message = m.buildMessage(
            msgtype             = d.TYPE_CON,
            token            = self.token,
            code             = self.code,
            messageId        = self.messageId,
            options          = self.options,
            payload          = self.payload,
            securityContext  = self.securityContext,
            partialIV        = self.requestSeq,
        )

        # send
        self.sendFunc(
            destIp           = self.destIp,
            destPort         = self.destPort,
            msg              = message,
        )

        # increment number of transmitted messages
        self.numTxCON       += 1

        # update FSM state
        self._setState(self.STATE_WAITFORACK)

        # kick FSM
        self._kickFsm()

    def _action_TXNON(self):

        # log
        log.debug('_action_TXNON()')

        # build message
        message = m.buildMessage(
            msgtype             = d.TYPE_NON,
            token            = self.token,
            code             = self.code,
            messageId        = self.messageId,
            options          = self.options,
            payload          = self.payload,
            securityContext  = self.securityContext,
            partialIV        = self.requestSeq,
        )

        # send
        self.sendFunc(
            destIp           = self.destIp,
            destPort         = self.destPort,
            msg              = message,
        )

        # update FSM state
        self._setState(self.STATE_WAITFORRESP)

        # kick FSM
        self._kickFsm()

    def _action_WAITFORACK(self):

        # log
        log.debug('_action_WAITFORACK()')

        startTime   = time.time()
        ackMaxWait  = self.ackTimeout*random.uniform(1, d.DFLT_ACK_RANDOM_FACTOR)
        while True:
            waitTimeLeft = startTime+ackMaxWait-time.time()
            if self.rxMsgEvent.wait(timeout=waitTimeLeft):
                # I got message
                with self.dataLock:
                    (timestamp,srcIp,srcPort,message) = self.LastRxPacket
                if isinstance(message,e.coapRc):
                    with self.dataLock:
                        self.coapError = message
                    return
                elif (
                        message['type']==d.TYPE_ACK and
                        message['messageId']==self.messageId
                    ):

                    # store ACK
                    with self.dataLock:
                        self.receivedACK = (timestamp,srcIp,srcPort,message)

                    # update FSM state
                    self._setState(self.STATE_ACKRX)

                    # kick FSM
                    self._kickFsm()
                    return
            else:
                # re-send

                # update FSM state
                self._setState(self.STATE_TXCON)

                # kick FSM
                self._kickFsm()
                return

    def _action_ACKRX(self):

        # log
        log.debug('_action_ACKRX()')

        with self.dataLock:
            assert self.receivedACK
            (timestamp,srcIp,srcPort,message) = self.receivedACK

        if message['code']==d.COAP_RC_NONE:
            # response NOT piggybacked

            # update FSM state
            self._setState(self.STATE_WAITFORRESP)

            # kick FSM
            self._kickFsm()
        else:
            # piggybacked response

            # successful end of FSM
            with self.dataLock:
               self.coapResponse = message

    def _action_WAITFOREXPIRATIONMID(self):

        # log
        log.debug('_action_WAITFOREXPIRATIONMID()')

        raise NotImplementedError()

    def _action_WAITFORRESP(self):

        # log
        log.debug('_action_WAITFORRESP()')

        startTime   = time.time()
        while True:
            waitTimeLeft = startTime+self.respTimeout-time.time()
            if self.rxMsgEvent.wait(timeout=waitTimeLeft):
                # I got message
                with self.dataLock:
                    (timestamp,srcIp,srcPort,message) = self.LastRxPacket
                if isinstance(message,e.coapRc):
                    with self.dataLock:
                        self.coapError = message
                    return
                elif (
                        (
                            message['type']==d.TYPE_CON or
                            message['type']==d.TYPE_NON
                        ) and
                        message['token']==self.token
                    ):

                    # store response
                    with self.dataLock:
                        self.receivedResp = (timestamp,srcIp,srcPort,message)

                    # update FSM state
                    self._setState(self.STATE_RESPRX)

                    # kick FSM
                    self._kickFsm()
                    return
            else:
                # this is an error case
                self.coapError   = e.coapTimeout('No Response received after {0}s'.format(
                        self.respTimeout,
                    )
                )
                return

    def _action_RESPRX(self):

        # log
        log.debug('_action_RESPRX()')

        with self.dataLock:
            (timestamp,srcIp,srcPort,message) = self.receivedResp

        # decide whether to ACK response
        if   message['type']==d.TYPE_CON:
            self._setState(self.STATE_TXACK)
        elif message['type']==d.TYPE_NON:
            # successful end of FSM
            with self.dataLock:
                self.coapResponse = message
        else:
            raise SystemError('unexpected message type {0}'.format(message['type']))

        # kick FSM
        self._kickFsm()

    def _action_TXACK(self):

        # log
        log.debug('_action_TXACK()')

        with self.dataLock:
            (timestamp,srcIp,srcPort,message) = self.receivedResp

        # build ACK
        message = m.buildMessage(
            msgtype             = d.TYPE_ACK,
            token            = None,
            code             = d.COAP_RC_NONE,
            messageId        = message['messageId'],
        )

        # send
        self.sendFunc(
            destIp           = message['srcId'],
            destPort         = message['srcPort'],
            msg              = message,
        )

        # successful end of FSM
        with self.dataLock:
            self.coapResponse = message

        # kick FSM
        self._kickFsm()

    #===== helpers

    def _kickFsm(self):
        self.fsmSem.release()

    def _setState(self,newState):
        with self.stateLock:
            self.state = newState
        log.debug('{0}: state={1}'.format(self.name,newState))

