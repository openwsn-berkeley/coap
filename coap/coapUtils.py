import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapUtils')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

def int2buf(val,len):
    returnVal  = []
    for i in range(len,0,-1):
        returnVal += [val>>(8*(i-1))&0xff]
    return returnVal
