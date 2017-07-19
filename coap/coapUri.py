import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('coapUri')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

import re

import coapUtils     as u
import coapOption    as o
import coapException as e
import coapDefines   as d

def uri2options(uri):
    '''
    \brief Converts a coap URI into a list of CoAP options.
    
    Examples:
    
    calling this function with uri="coap://[aaaa::1]:1234/test1/test2"
    returns 
    (
        'aaaa::1',
        1234,
        (
           [Uri-Path('test1'),
           Uri-Path('test2')],
        ),
    )
    
    Calling this function with uri="http://[aaaa::1]/test1/test2"
    raises a coapMalformattedUri.
    
    \param[in] uri A string representing a CoAP URI.
    
    \raises coapMalformattedUri When the string passed in the uri parameter
        is not a valid CoAP URI.
    
    \return A tuple with the following elements;
        - at index 0, the destination IP address or host name (a string).
        - at index 1, the UDP port, possibly default CoAP port if none is
          explicitly specified..
        - at index 2, a tuple of CoAP options, i.e. (sub-)instances of the
          #coapOption objects.
    '''
    options   = []
    
    log.debug('uri      : {0}'.format(uri))
    
    # scheme
    if not uri.startswith(d.COAP_SCHEME):
        raise e.coapMalformattedUri('does not start with {0}'.format(d.COAP_SCHEME))
    
    # remove scheme
    uri       = uri.split(d.COAP_SCHEME,1)[1]
    
    # host and port
    host      = None
    port      = None
    hostPort  = uri.split('/')[0]
    if (not host) or (not port):
        # try format [aaaa::1]:1244
        m = re.match('\[([0-9a-fA-F:]+)\]:([0-9]+)',hostPort)
        if m:
            host   =     m.group(1)
            port   = int(m.group(2))
    if (not host) or (not port):
        # try format [aaaa::1]
        m = re.match('\[([0-9a-fA-F:]+)\]',hostPort)
        if m:
            host   = m.group(1)
            port   = d.DEFAULT_UDP_PORT
    if (not host) or (not port):
        # try formats:
        #    123.123.123.123:1234
        m = re.match('([0-9.]+):([0-9]+)',hostPort)
        if m:
            host   =     '::ffff:{0}'.format(m.group(1))
            port   = int(m.group(2))
    if (not host) or (not port):
        # try formats:
        #    www.example.com:1234
        m = re.match('([0-9a-zA.\-\_]+):([0-9]+)',hostPort)
        if m:
            host   =     m.group(1)
            port   = int(m.group(2))
    if (not host) or (not port):
        # try formats:
        #    123.123.123.123
        m = re.match('([0-9.]+)',hostPort)
        if m:
            host   = '::ffff:{0}'.format(m.group(1))
            port   = d.DEFAULT_UDP_PORT
    if (not host) or (not port):
        # try formats:
        #    www.example.com
        m = re.match('([0-9a-zA-Z.\-\_]+)', hostPort)
        if m:
            host = m.group(1)
            port = d.DEFAULT_UDP_PORT
    if (not host) or (not port):
        raise e.coapMalformattedUri('invalid host and port {0}'.format(hostPort))
    
    # log
    log.debug('host     : {0}'.format(host))
    log.debug('port     : {0}'.format(port))
    
    # remove hostPort
    uri       = uri.split(hostPort,1)[1]

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
    
    host=host.lower()
    host=u.trimAddress(host)
    
    return (host,port,options)

def options2path(options):
    returnVal = []
    for option in options:
        if isinstance(option,o.UriPath):
            returnVal += [option.path]
    returnVal = '/'.join(returnVal)
    return returnVal
