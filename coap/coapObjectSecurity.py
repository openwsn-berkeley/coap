import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapObjectSecurity')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import cbor
import hkdf
import hashlib
import coapDefines        as d
import coapException      as e
import coapOption         as o
import coapMessage        as m
import coapUtils          as u

import binascii
from Crypto.Cipher import AES

def protectMessage(context, version, code, options = [], payload = [], partialIV = None):
    '''
    \brief A function which protects the outgoing CoAP message using OSCOAP.

    This function protects the outgoing CoAP message determined by input parameters according to
    draft-ietf-core-object-security-03.
    \param[in] Security context to use to protect the outgoing message.
    \param[in] version CoAP version field of the outgoing message.
    \param[in] code CoAP code field of the outgoing message.
    \param[in] options A list of options to be included in the outgoing CoAP message.
    \param[in] payload Payload of the outgoing CoAP message.
    \param[in] partialIV Partial IV either to be used to protect the request or the one received as part of the
    corresponding request to protect the response. Expected string of length given by the context algorithm.

    \return A tuple with the following elements:
        - element 0 is the list of outer (integrity-protected and unprotected) CoAP options.
        - element 1 is the protected payload.
    '''

    # split the options to class E (encrypted and integrity protected), I (integrity protected) and U (unprotected)
    (optionsClassE, optionsClassI, optionsClassU) = _splitOptions(options)

    objectSecurityOption = objectSecurityOptionLookUp(options)

    # construct plaintext
    plaintext = []
    plaintext += m.encodeOptions(optionsClassE)
    plaintext += m.encodePayload(payload)
    plaintext = u.buf2str(plaintext) # convert to string

    # construct aad

    requestSeq = partialIV.lstrip('\0')

    # construct nonce
    if _isRequest(code):
        requestKid = context.senderID
        nonce = u.xorStrings(context.senderIV, partialIV)
    else:   # response
        requestKid = context.recipientID
        nonce = u.xorStrings(u.flipFirstBit(context.senderIV), partialIV)

    aad = _constructAAD(version,
                        code,
                        u.buf2str(m.encodeOptions(optionsClassI)),
                        context.aeadAlgorithm.value,
                        requestKid,
                        requestSeq)

    ciphertext = context.aeadAlgorithm.authenticateAndEncrypt(
        aad=aad,
        plaintext=plaintext,
        key=context.senderKey,
        nonce=nonce)

    if not _isRequest(code): # do not encode sequence number and kid in the response
        requestSeq = []
        requestKid = []

    # encode according to OSCOAP draft
    finalPayload = _encodeCompressedCOSE(requestSeq, requestKid, ciphertext)

    if payload:
        return (optionsClassI+optionsClassU, finalPayload)
    else:
        objectSecurityOption.setValue(finalPayload)
        return (optionsClassI+optionsClassU, [])

def unprotectMessage(context, version, code, options = [], ciphertext = [], partialIV=None):
    '''
    \brief A function which verifies and decrypts the incoming CoAP message using OSCOAP.

    This function verifies the incoming CoAP message determined by input parameters according to
    draft-ietf-core-object-security-03.
    \param[in] Security context to use to verify+decrypt the outgoing message.
    \param[in] version CoAP version field of the incoming message.
    \param[in] code CoAP code field of the incoming message.
    \param[in] options A list of 'outer' options that are not encrypted.
    \param[in] ciphertext Ciphertext of the incoming CoAP message.
    \param[in] partialIV In case of request, partialIV corresponds to the one parsed from the message. In case
     of response, it corresponds to the appropriate partialIV used in request. Expected string of length given
     by the context algorithm.

    \return A tuple with the following elements:
        - element 0 is the list of inner (encrypted) CoAP options.
        - element 1 is the decrypted payload.
    '''
    assert objectSecurityOptionLookUp(options)

    (optionsClassE, optionsClassI, optionsClassU) = _splitOptions(options)

    if optionsClassE:
        raise e.messageFormatError('invalid oscoap message. E-class option present in the outer message')

    if _isRequest(code):
        requestKid = context.recipientID
        if not context.replayWindowLookup(u.buf2int(u.str2buf(partialIV))):
            raise e.oscoapError('Replay protection failed')
    else:
        requestKid = context.senderID

    requestSeq = partialIV.lstrip('\0')

    aad = _constructAAD(version,
                        code,
                        u.buf2str(m.encodeOptions(optionsClassI)),
                        context.aeadAlgorithm.value,
                        requestKid,
                        requestSeq)

    # construct nonce
    if _isRequest(code): # verifying request
        nonce = u.xorStrings(context.recipientIV, partialIV)
    else: # verifying response
        nonce = u.xorStrings(u.flipFirstBit(context.recipientIV), partialIV)

    try:
        plaintext = context.aeadAlgorithm.authenticateAndDecrypt(
            aad=aad,
            ciphertext=u.buf2str(ciphertext),
            key=context.recipientKey,
            nonce=nonce)
    except e.oscoapError:
        raise

    if _isRequest(code):
        context.replayWindowUpdate(u.buf2int(u.str2buf(partialIV)))

    # returns a tuple (innerOptions, payload)
    return m.decodeOptionsAndPayload(u.str2buf(plaintext))

def parseObjectSecurity(optionValue, payload):
    if optionValue and payload:
        raise e.messageFormatError('invalid oscoap message, both payload and value are set.')
    elif optionValue:
        buffer = optionValue
    elif payload:
        buffer = payload
    else:
        raise e.messageFormatError('invalid oscoap message. no value or payload found.')

    returnVal = {}

    # decode first byte
    pivsz = (buffer[0] >> 0) & 0x07
    k = (buffer[0] >> 3) & 0x01
    reserved = (buffer[0] >> 4) & 0x0f

    if reserved:
        raise e.messageFormatError('invalid oscoap message. reserved bits set.')

    buffer = buffer[1:]

    returnVal['partialIV'] = []
    if pivsz:
        returnVal['partialIV'] = buffer[:pivsz]
        buffer = buffer[pivsz:]

    returnVal['kid'] = []
    if k:
        kidLength = buffer[0]
        buffer = buffer[1:]
        returnVal['kid'] = buffer[:kidLength]
        buffer = buffer[kidLength:]

    returnVal['ciphertext'] = buffer

    return returnVal

def getRequestSecurityParams(objectSecurityOption):
    if objectSecurityOption:
        context = objectSecurityOption.context
        newSequenceNumber = objectSecurityOption.context.getSequenceNumber()
        # convert sequence number to string that is the length of the IV
        newSequenceNumber = u.buf2str(u.int2buf(newSequenceNumber, context.aeadAlgorithm.ivLength))
        return (context, newSequenceNumber)
    else:
        return (None, None)

def objectSecurityOptionLookUp(options):
    for option in options:
        if isinstance(option, o.ObjectSecurity):
            return option
    return None

'''
   7 6 5 4 3 2 1 0
  +-+-+-+-+-+-+-+-+  k: kid flag bit
  |0 0 0 0|k|pivsz|  pivsz: Partial IV size (3 bits)
  +-+-+-+-+-+-+-+-+

+-------+---------+------------+
|       | Request | Resp with- |
|       |         | out observe|
+-------+---------+------------+
|     k |    1    |     0      |
| pivsz |  > 0    |     0      |
+-------+---------+------------+

'''
def _encodeCompressedCOSE(partialIV, kid, ciphertext):
    buffer = []

    if kid:
        kidFlag = 1
    else:
        kidFlag = 0

    buffer += [ kidFlag << 3 | len(partialIV) ] # flag byte

    if partialIV:
        buffer += u.str2buf(partialIV)
    if kid:
        buffer += [len(kid)]
        buffer += u.str2buf(kid)

    buffer += u.str2buf(ciphertext)

    return buffer

def _constructAAD(version, code, optionsSerialized, aeadAlgorithm, requestKid, requestSeq):

    externalAad = cbor.dumps([
        version,
        code,
        optionsSerialized,
        aeadAlgorithm,
        requestKid,
        requestSeq
    ])

    # from https://tools.ietf.org/html/draft-ietf-cose-msg-24#section-5.3
    encStructure = [
        unicode('Encrypt0'),
        '',  # an empty byte string
        externalAad
    ]

    return cbor.dumps(encStructure)

def _splitOptions(options):
    classE = []
    classI = []
    classU = []

    for option in options:
        if option.oscoapClass == d.OSCOAP_CLASS_E:
            classE += [option]
        if option.oscoapClass == d.OSCOAP_CLASS_I:
            classI += [option]
        if option.oscoapClass == d.OSCOAP_CLASS_U:
            classU += [option]
    return (classE, classI, classU)

def _isRequest(code):
    if code in d.METHOD_ALL:  # request
        return True
    elif code in d.COAP_RC_ALL:
        return False
    else:
        raise NotImplementedError()

class CCMAlgorithm():

    #======================== abstract members ================================

    def value(self):
        raise NotImplementedError

    def keyLength(self):
        raise NotImplementedError

    def ivLength(self):
        raise NotImplementedError

    def tagLength(self):
        raise NotImplementedError

    def maxSequenceNumber(self):
        raise NotImplementedError

    # ======================== public ==========================================

    def authenticateAndEncrypt(self, aad, plaintext, key, nonce):
        if self.keyLength != len(key):
            raise e.oscoapError('Key length mismatch.')

        if self.ivLength != len(nonce):
            raise e.oscoapError('IV length mismatch.')

        cipher = AES.new(key, AES.MODE_CCM, nonce, mac_len=self.tagLength)
        if aad:
            cipher.update(aad)
        ciphertext = cipher.encrypt(plaintext)
        digest = cipher.digest()
        ciphertext = ciphertext + digest
        return ciphertext

    def authenticateAndDecrypt(self, aad, ciphertext, key, nonce):
        digest = ciphertext[-self.tagLength:]
        ciphertext = ciphertext[:-self.tagLength]
        cipher = AES.new(key, AES.MODE_CCM, nonce, mac_len=self.tagLength)
        if aad:
            cipher.update(aad)
        try:
            plaintext = cipher.decrypt(ciphertext)
            cipher.verify(digest)
            return plaintext
        except ValueError:
            raise e.oscoapError('Invalid tag verification.')

class AES_CCM_64_64_128(CCMAlgorithm):
    value               = d.COSE_AES_CCM_64_64_128
    keyLength           = 16    # 128 bits
    ivLength            = 7
    tagLength           = 8
    maxSequenceNumber   = 2 ** (min(ivLength*8, 56) - 1) - 1

class AES_CCM_16_64_128(CCMAlgorithm):
    value       = d.COSE_AES_CCM_16_64_128
    keyLength   = 16
    ivLength    = 13
    tagLength   = 8
    maxSequenceNumber = 2 ** (min(ivLength * 8, 56) - 1) - 1

class SecurityContext:
    REPLAY_WINDOW_SIZE = 64
    def __init__(self, masterSecret, senderID, recipientID, aeadAlgorithm = AES_CCM_64_64_128(), masterSalt = '', hashFunction = hashlib.sha256):

        # Common context
        self.aeadAlgorithm = aeadAlgorithm
        self.hashFunction = hashFunction
        self.masterSecret = masterSecret
        self.masterSalt = masterSalt

        # Sender context
        self.senderID = senderID
        self.senderKey = self._hkdfDeriveParameter(self.hashFunction,
                                                   self.masterSecret,
                                                   self.masterSalt,
                                                   self.senderID,
                                                   self.aeadAlgorithm.value,
                                                   'Key',
                                                   self.aeadAlgorithm.keyLength
                                                   )

        self.senderIV = self._hkdfDeriveParameter(self.hashFunction,
                                                  self.masterSecret,
                                                  self.masterSalt,
                                                  self.senderID,
                                                  self.aeadAlgorithm.value,
                                                  'IV',
                                                  self.aeadAlgorithm.ivLength
                                                  )
        self.sequenceNumber = 0

        # Recipient context
        self.recipientID = recipientID
        self.recipientKey = self._hkdfDeriveParameter(self.hashFunction,
                                                   self.masterSecret,
                                                   self.masterSalt,
                                                   self.recipientID,
                                                   self.aeadAlgorithm.value,
                                                   'Key',
                                                   self.aeadAlgorithm.keyLength
                                                    )
        self.recipientIV = self._hkdfDeriveParameter(self.hashFunction,
                                                   self.masterSecret,
                                                   self.masterSalt,
                                                   self.recipientID,
                                                   self.aeadAlgorithm.value,
                                                   'IV',
                                                   self.aeadAlgorithm.ivLength
                                                   )
        self.replayWindow = [0]

    # ======================== public ==========================================

    def getSequenceNumber(self):
        self.sequenceNumber += 1
        if self.sequenceNumber > self.aeadAlgorithm.maxSequenceNumber:
            raise e.oscoapError('Reached maximum sequence number.')
        return self.sequenceNumber

    def getIVLength(self):
        return self.aeadAlgorithm.ivLength

    def replayWindowLookup(self, sequenceNumber):
        if sequenceNumber in self.replayWindow:
            return False

        if sequenceNumber < min(self.replayWindow):
            return False

        return True

    def replayWindowUpdate(self, sequenceNumber):
        assert sequenceNumber > min(self.replayWindow)
        assert sequenceNumber not in self.replayWindow

        if len(self.replayWindow) == self.REPLAY_WINDOW_SIZE:
            self.replayWindow.remove(min(self.replayWindow))

        self.replayWindow += [sequenceNumber]

    # ======================== private ==========================================

    def _hkdfDeriveParameter(self, hashFunction, masterSecret, masterSalt, id, algorithm, type, length):

        info = cbor.dumps([
            id,
            algorithm,
            unicode(type), # encode as text string
            length
        ])

        extract = hkdf.hkdf_extract(salt=masterSalt, input_key_material=masterSecret, hash=hashFunction)
        expand = hkdf.hkdf_expand(pseudo_random_key=extract, info=info, length=length, hash=hashFunction)

        return expand

