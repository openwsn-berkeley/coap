import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapResource')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapException as e

class coapResource(object):
    
    def __init__(self,uri,callback):
        
        assert type(uri)==str
        assert callable(callback)
        
        # store params
        self.uri      = uri
        self.callback = callback
    
    #======================== abstract methods ======================
    
    def GET(options=[]):
        raise e.coapRcMethodNotAllowed()
    
    def PUT(options=[],payload=None):
        raise e.coapRcMethodNotAllowed()
    
    def POST(options=[],payload=None):
        raise e.coapRcMethodNotAllowed()
    
    def DELETE(options=[]):
        raise e.coapRcMethodNotAllowed()