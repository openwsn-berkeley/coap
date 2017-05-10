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

import os
import binascii
from Crypto.Cipher import AES

def protectMessage(context, header, options, payload=[]):
    return payload

def unprotectMessage(message):
    # find appropriate context
    # decrypt message for the given context
    # parse unencrypted message options
    return message

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
    value       = d.COSE_AES_CCM_64_64_128
    keyLength   = 16    # 128 bits
    ivLength    = 7
    tagLength   = 8

class AES_CCM_16_64_128(CCMAlgorithm):
    value       = d.COSE_AES_CCM_16_64_128
    keyLength   = 16
    ivLength    = 13
    tagLength   = 8

class SecurityContext:
    def __init__(self, masterSecret, senderID, recipientID, aeadAlgorithm = AES_CCM_64_64_128(), masterSalt = "", hashFunction = hashlib.sha256):

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

