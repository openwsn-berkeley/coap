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

import os
import binascii
from Crypto.Cipher import AES

def protectMessage(version, code, options = [], payload = [], requestPartialIV = None):
    '''
    \brief A function which protects the outgoing CoAP message using OSCOAP.

    This function protects the outgoing CoAP message determined by input parameters according to
    draft-ietf-core-object-security-03. It expects one of the passed options to be an Object-Security
    option with security context set. In case there is no such option in the options list, the function
    returns the payload and options unmodified.
    \param[in] version CoAP version field of the outgoing message.
    \param[in] code CoAP code field of the outgoing message.
    \param[in] options A list of options to be included in the outgoing CoAP message.
    \param[in] payload Payload of the outgoing CoAP message.
    \param[in] requestPartialIV Partial IV received as part of the corresponding request.

    \return A tuple with the following elements:
        - element 0 is the list of outer (integrity-protected and unprotected) CoAP options. If no Object-Security
        option is present, option list is returned unmodified.
        - element 1 is the protected payload. If no Object-Security option is present, payload is returned unmodified.
    '''
    # check if Object Security option is present in the options list
    objectSecurity = _objectSecurityOptionLookUp(options)

    if objectSecurity: # Object-Security option is present, protect the message
        assert objectSecurity.context

        # split the options to class E (encrypted and integrity protected), I (integrity protected) and U (unprotected)
        optionsClassE, optionsClassI, optionsClassU = _splitOptions(options)

        # construct plaintext
        plaintext = []
        plaintext += m.encodeOptions(optionsClassE)
        plaintext += m.encodePayload(payload)
        plaintext = u.buf2str(plaintext) # convert to string

        # construct aad

        requestKid = objectSecurity.context.senderID

        if code in d.METHOD_ALL: # request
            sequenceNumber = objectSecurity.context.getSequenceNumber()

            # construct partialIV string that is the length of the IV
            partialIV = u.buf2str(u.int2buf(sequenceNumber, objectSecurity.context.aeadAlgorithm.ivLength))

            # strip leading zeros
            requestSeq = partialIV.lstrip('\0')
            # construct nonce
            nonce = u.xorStrings(objectSecurity.context.senderIV, partialIV)

        elif code in d.COAP_RC_ALL:  # response
            assert requestPartialIV
            requestSeq = requestPartialIV.lstrip('\0')
            nonce = u.xorStrings(u.flipFirstBit(objectSecurity.context.senderIV), requestPartialIV)

        externalAad = cbor.dumps([
            version,
            code,
            m.encodeOptions(optionsClassI),
            objectSecurity.context.aeadAlgorithm.value,
            requestKid,
            requestSeq
        ])

        # from https://tools.ietf.org/html/draft-ietf-cose-msg-24#section-5.3
        encStructure = [
            "Encrypt0",
            '', # an empty string
            externalAad
        ]

        aad = cbor.dumps(encStructure)

        ciphertext = objectSecurity.context.aeadAlgorithm.authenticateAndEncrypt(
            aad=aad,
            plaintext=plaintext,
            key=objectSecurity.context.senderKey,
            nonce=nonce)

        # encode according to OSCOAP draft
        finalPayload = _encodeCompressedCOSE(requestSeq, requestKid, ciphertext)

        if payload:
            return (optionsClassI+optionsClassU, finalPayload)
        else:
            objectSecurity.setValue(finalPayload)
            return (optionsClassI+optionsClassU, [])

    else: # Object-Security option is not present, return the options and payload as-is
        return (options, payload)

'''
   7 6 5 4 3 2 1 0
  +-+-+-+-+-+-+-+-+  k: kid flag bit
  |0 0 0 0|k|pivsz|  pivsz: Partial IV size (3 bits)
  +-+-+-+-+-+-+-+-+

+-------+---------+------------+-----------+
|       | Request | Resp with- | Resp with |
|       |         | out observe| observe   |
+-------+---------+------------+-----------+
|     k |    1    |     0      |      0    |
| pivsz |  > 0    |     0      |    > 0    |
+-------+---------+------------+-----------+

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


def unprotectMessage(message):
    # decode message
    # find appropriate context
    # decrypt message for the given context
    # parse unencrypted message options
    return message

def _objectSecurityOptionLookUp(options):
    for option in options:
        if isinstance(option, o.ObjectSecurity):
            return option
    return None

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
    return classE, classI, classU

class CCMAlgorithm():
    def authenticateAndEncrypt(self, aad, plaintext, key, nonce):
        if self.keyLength != len(key):
            raise e.oscoapError("Key length mismatch.")

        if self.ivLength != len(nonce):
            raise e.oscoapError("IV length mismatch.")

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
            raise e.oscoapError("Invalid tag verification.")

class AES_CCM_64_64_128(CCMAlgorithm):
    value               = d.COSE_AES_CCM_64_64_128
    keyLength           = 16    # 128 bits
    ivLength            = 7
    tagLength           = 8
    maxSequenceNumber   = 2**(min(ivLength*8, 56) - 1) - 1

class AES_CCM_16_64_128(CCMAlgorithm):
    value       = d.COSE_AES_CCM_16_64_128
    keyLength   = 16
    ivLength    = 13
    tagLength   = 8
    maxSequenceNumber = 2 ** (min(ivLength * 8, 56) - 1) - 1

class SecurityContext:
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
        self.replayWindow = []

    def getSequenceNumber(self):
        self.sequenceNumber += 1
        if self.sequenceNumber > self.aeadAlgorithm.maxSequenceNumber:
            raise e.oscoapError("Reached maximum sequence number.")
        return self.sequenceNumber

    def _hkdfDeriveParameter(self, hashFunction, masterSecret, masterSalt, id, algorithm, type, length):

        info = cbor.dumps([
            id,
            algorithm,
            type,
            length
        ])

        extract = hkdf.hkdf_extract(salt=masterSalt, input_key_material=masterSecret, hash=hashFunction)
        expand = hkdf.hkdf_expand(pseudo_random_key=extract, info=info, length=length, hash=hashFunction)

        return expand

