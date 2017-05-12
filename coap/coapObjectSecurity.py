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

def protectMessage(version, code, options = [], payload = []):
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

        sequenceNumber = objectSecurity.context.getSequenceNumber()

        # construct partialIV string that is the length of the IV
        partialIV = u.buf2str(u.int2buf(sequenceNumber, objectSecurity.context.aeadAlgorithm.ivLength))
        # strip leading zeros
        requestSeq = partialIV.lstrip(b'\0')
        # construct nonce
        nonce = u.xorStrings(objectSecurity.context.senderIV, partialIV)

        aad = [
            version,
            code,
            m.encodeOptions(optionsClassI),
            objectSecurity.context.aeadAlgorithm.value,
            requestKid,
            requestSeq
        ]

        aadEncoded = cbor.dumps(aad)

        ciphertext = objectSecurity.context.aeadAlgorithm.authenticateAndEncrypt(
            aad=aadEncoded,
            plaintext=plaintext,
            key=objectSecurity.context.senderKey,
            nonce=nonce)

        ciphertext = u.str2buf(ciphertext) # convert back to list

        if payload:
            return optionsClassI+optionsClassU, ciphertext
        else:
            objectSecurity.setValue(ciphertext)
            return optionsClassI+optionsClassU, []

    else: # Object-Security option is not present, return the options and payload as-is
        return options, payload

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
    def __init__(self, masterSecret, senderID, recipientID, aeadAlgorithm = AES_CCM_64_64_128(), masterSalt = [], hashFunction = hashlib.sha256):

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

