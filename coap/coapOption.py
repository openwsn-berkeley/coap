import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapOption')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapDefines

class coapOption(object):
    
    def __init__(self,optionNumber):
        # store params
        self.optionNumber = optionNumber

class UriPath(coapOption):
    
    def __init__(self,path):
        
        # store params
        self.path = path
        
        # initialize parent
        coapOption.__init__(self,coapDefines.OPTION_NUM_URIPATH)
    
    def __repr__(self):
        return 'UriPath(path={0})'.format(self.path)
