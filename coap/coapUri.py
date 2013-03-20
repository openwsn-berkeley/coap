import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapUri')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import re

import coapDefines   as d
import coapException as e
import coapOption    as o

def uri2options(uri):
    '''
    \brief Converts a coap URI into a list of CoAP options.
    
    Examples:
    
    calling this function with uri="coap://[aaaa::1]/test1/test2"
    returns 
    (
        'aaaa::1'
        [Uri-Path('test1'),Uri-Path('test2')]
    )
    
    calling this function with uri="http://[aaaa::1]/test1/test2"
    raises a coapMalformattedUri.
    
    calling this function with uri="coap://example.com/test1/test2"
    returns 
    (
        'aaaa::1'
        [Uri-Path('test1'),Uri-Path('test2')]
    )
    
    \param[in] uri A string representing a CoAP URI.
    
    \raises coapMalformattedUri When the string passed in the uri parameter
        is not a valid CoAP URI.
    
    \return A tuple with the following 2 elements;
        - at index 0, the destination IP address. This is useful when the URI contains
          a DNS name instead of an IP addres
        - at index 1, a list of CoAP options, i.e. (sub-)instances of the
          #coapOption objects.
    '''
    options   = []
    
    log.debug('uri      : {0}'.format(uri))
    
    # scheme
    if not uri.startswith(d.COAP_SCHEME):
        raise e.coapMalformattedUri('does not start with {0}'.format(d.COAP_SCHEME))
    
    # remove scheme
    uri       = uri.split(d.COAP_SCHEME,1)[1]
    
    # ip address and port
    ip        = None
    port      = None
    ipPort    = uri.split('/')[0]
    if (not ip) or (not port):
        m = re.match('\[([0-9a-fA-F:]+)\]:([0-9]+)',ipPort)
        if m:
            ip     =     m.group(1)
            port   = int(m.group(2))
    if (not ip) or (not port):
        m = re.match('\[([0-9a-fA-F:]+)\]',ipPort)
        if m:
            ip     = m.group(1)
            port   = d.DEFAULT_UDP_PORT
    if (not ip) or (not port):
        m = re.match('([0-9a-zA-Z.]+):([0-9]+)',ipPort)
        if m:
            raise NotImplementedError
    if (not ip) or (not port):
        m = re.match('([0-9a-zA-Z.]+)',ipPort)
        if m:
            raise NotImplementedError
    if (not ip) or (not port):
        raise e.coapMalformattedUri('invalid host and port {0}'.format(temp))
    
    # log
    log.debug('ip       : {0}'.format(ip))
    log.debug('port     : {0}'.format(port))
    
    # remove ipPort
    uri       = uri.split(ipPort,1)[1]
    
    # Uri-path
    paths     = [p for p in uri.split('?')[0].split('/') if p]
    log.debug('paths    : {0}'.format(paths))
    for p in paths:
        options += [o.UriPath(path=p)]
    
    # Uri-query
    if len(uri.split('?'))>1:
        queries   = [q for q in uri.split('?')[1].split('&') if q]
        log.debug('queries  : {0}'.format(queries))
        raise NotImplementedError()
    
    return (ip,port,options)