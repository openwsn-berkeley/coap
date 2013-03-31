import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('snoopyDispatcher')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import threading
import struct
import time

from coap import coapUtils as u

from pydispatch import dispatcher

class snoopyDispatcher(threading.Thread):
    
    def __init__(self,filename):
        
        # log
        log.debug('creating instance')
        
        # store params
        self.filename   = filename
        
        # local variables
        self.gotMsgSem  = threading.Semaphore()
        self.pcapFile   = open(self.filename,'wb')
        
        # write PCAP file header
        self._writePcapHeader()
        
        # initialize the parent
        threading.Thread.__init__(self)
        
        # give this thread a name
        self.name       = 'snoopyDispatcher'
        
        # connect to dispatcher
        dispatcher.connect(
            receiver = self._messageNotification,

        )
    
    #======================== public ==========================================
    
    def close(self):
        
        # disconnect from dispatcher
        dispatcher.disconnect(
            receiver = self._messageNotification,
        )
        
        # close pcap file
        self.pcapFile.close()
        
        # stop
        self.goOn    = False
        self.gotMsgSem.release()
    
    #======================== private =========================================
    
    def run(self):
        try:
            while self.goOn:
                self.gotMsgSem.acquire()
        except Exception as err:
            log.critical(u.formatCrashMessage(
                    threadName = self.name,
                    error      = err
                )
            )
    
    def _messageNotification(self,signal,sender,data):
        
        timestamp  = time.time()
        
        # log
        log.debug("{0}:{1}->{2}:{3}: {4}".format(
                sender[0],
                sender[1],
                signal[0],
                signal[1],
                u.formatBuf(data),
            )
        )
        
        srcIp      = u.ipv6AddrString2Bytes(sender[0])
        srcPort    = sender[1]
        destIp     = u.ipv6AddrString2Bytes(signal[0])
        destPort   = signal[1]
        
        # log in pcap
        self._writePcapMessage(timestamp,srcIp,destIp,srcPort,destPort,data)
        
        # release the lock
        self.gotMsgSem.release()
    
    def _writePcapHeader(self):
        
        # format PCAP file header
        pcapFileHeader = struct.pack(
            'IHHiIII',
            0xa1b2c3d4,      # magic_number
            2,               # version_major
            4,               # version_minor
            0,               # thiszone
            0,               # sigfigs
            0xffff,          # snaplen
            101,             # network (101==LINKTYPE_RAW)
        )
        
        # write to file
        self.pcapFile.write(pcapFileHeader)
    
    def _writePcapMessage(self,timestamp,srcIp,destIp,srcPort,destPort,payload):
        
        bytesToWrite    = []
        
        # IPv6 message
        bytesToWrite   += [0x06<<4]                   # version + traffic_class[high]
        bytesToWrite   += [0x00]*3                    # traffic_class[low] + flow_label
        bytesToWrite   += u.int2buf(8+len(payload),2) # payload length (incl. UDP header)
        bytesToWrite   += [17]                        # next header (17==UDP)
        bytesToWrite   += [64]                        # hop limit
        bytesToWrite   += srcIp                       # source address
        bytesToWrite   += destIp                      # destination addres
        
        # UDP header
        bytesToWrite   += u.int2buf(srcPort,2)        # source port
        bytesToWrite   += u.int2buf(destPort,2)       # destination port
        bytesToWrite   += u.int2buf(len(payload),2)   # length
        bytesToWrite   += u.int2buf(
            u.calcUdpCheckSum(
                srcIp,
                destIp,
                srcPort,
                destPort,
                payload,
            ),
            2
        )                                             # checksum
        
        # payload
        bytesToWrite   += payload                     # payload
        
        # format PCAP message header
        ts_sec          = int(timestamp)
        ts_usec         = int((timestamp-ts_sec)*1000000)
        pcapMsgHeader   = struct.pack(
            'IIII',
            ts_sec,                                   # ts_sec
            ts_usec,                                  # ts_usec
            len(bytesToWrite),                        # incl_len
            len(bytesToWrite),                        # orig_len
        )
        
        # write to file
        stringToWrite   = ''.join(
           [pcapMsgHeader]+[''.join([chr(b) for b in bytesToWrite])]
        )
        self.pcapFile.write(stringToWrite)
        self.pcapFile.flush()
        
        log.debug('written {0} bytes'.format(len(stringToWrite)))
