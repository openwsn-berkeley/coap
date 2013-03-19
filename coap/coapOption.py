import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapOption')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

class coapOption(object):
    
    def __init__(self):
        pass

class UriPath(coapOption):
    
    def __init__(self,path):
        
        # store params
        self.path = path
        
        # initialize parent
        coapOption.__init__(self)
