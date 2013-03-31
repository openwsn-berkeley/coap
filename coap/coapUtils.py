import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapUtils')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import traceback

#===== converting

def int2buf(val,len):
    returnVal  = []
    for i in range(len,0,-1):
        returnVal += [val>>(8*(i-1))&0xff]
    return returnVal

def buf2int(buf):
    returnVal  = 0
    for i in range(len(buf)):
        returnVal += buf[i]<<(8*(len(buf)-1-i))
    return returnVal

#===== formatting

def formatBuf(buf):
    return '({0} bytes) {1}'.format(
        len(buf),
        '-'.join(['%02x'%b for b in buf])
    )

def formatCrashMessage(threadName,error):
    returnVal  = []
    returnVal += ['\n']
    returnVal += ['======= crash in {0} ======='.format(threadName)]
    returnVal += ['Error:']
    returnVal += [str(error)]
    returnVal += ['\ncall stack:\n']
    returnVal += [traceback.format_exc()]
    returnVal += ['\n']
    returnVal  = '\n'.join(returnVal)
    return returnVal