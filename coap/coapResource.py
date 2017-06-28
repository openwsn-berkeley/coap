import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapResource')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import coapException        as e
import coapDefines          as d
import coapObjectSecurity   as oscoap

class coapResource(object):
    
    def __init__(self,path):
        
        assert type(path)==str
        
        # store params
        self.path     = path

        self.securityBinding = None
    
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

    def addSecurityBinding(self, binding):
        (ctx, authorizedMethods) = binding
        assert isinstance(authorizedMethods, list)
        for method in authorizedMethods:
            assert method in d.METHOD_ALL

        log.debug('adding security binding for resource={0}, context={1}, authorized methods={2}'.format(self.path,
                                                                                                         ctx,
                                                                                                         authorizedMethods))
        self.securityBinding = binding


    def getSecurityBinding(self):
        if self.securityBinding:
            return self.securityBinding
        else:
            # if no context is bound to the resource, all methods are authorized
            return (None, d.METHOD_ALL)

