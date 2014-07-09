import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapResource')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapException as e

class coapResource(object):
    
    def __init__(self,path):
        
        assert type(path)==str
        
        # store params
        self.path     = path
    
    #======================== abstract methods ================================
    
    def GET(self,options=[]):
        raise e.coapRcMethodNotAllowed()
    
    def PUT(self,options=[],payload=None):
        raise e.coapRcMethodNotAllowed()
    
    def POST(self,options=[],payload=None):
        raise e.coapRcMethodNotAllowed()
    
    def DELETE(self,options=[]):
        raise e.coapRcMethodNotAllowed()
    
    #======================== public ==========================================
    
    def matchesPath(self,pathToMatch):
        log.debug('"{0}" matches "{1}"?'.format(pathToMatch,self.path))
        temp_path        = self.path.lstrip('/').rstrip('/')
        temp_pathToMatch = pathToMatch.lstrip('/').rstrip('/')
        if temp_path==temp_pathToMatch:
            return True
        else:
            return False
