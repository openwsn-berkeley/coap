import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapResource')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapException as e

class coapResource(object):
    
    def __init__(self,uri):
        
        assert type(uri)==str
        
        # store params
        self.uri      = uri
    
    #======================== abstract methods ======================
    
    def GET(self,options=[]):
        raise e.coapRcMethodNotAllowed()
    
    def PUT(self,options=[],payload=None):
        raise e.coapRcMethodNotAllowed()
    
    def POST(self,options=[],payload=None):
        raise e.coapRcMethodNotAllowed()
    
    def DELETE(self,options=[]):
        raise e.coapRcMethodNotAllowed()