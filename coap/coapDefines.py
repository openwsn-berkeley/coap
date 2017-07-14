DEFAULT_UDP_PORT                       = 5683
COAP_VERSION                           = 1
COAP_PAYLOAD_MARKER                    = 0xff
COAP_SCHEME                            = 'coap://'

# OSCOAP option classes
OSCOAP_CLASS_E                         = 'E'  # encrypted and integrity protected
OSCOAP_CLASS_I                         = 'I'  # integrity protected
OSCOAP_CLASS_U                         = 'U'  # unprotected

# Default transmission parameters
DFLT_ACK_TIMEOUT                       = 20   # in s. 
DFLT_ACK_RANDOM_FACTOR                 = 1.5  # ACK timeout in [DFLT_ACK_TIMEOUT..DFLT_ACK_TIMEOUT*DFLT_ACK_RANDOM_FACTOR]
DFLT_MAX_RETRANSMIT                    = 4    # max number of retransmissions for NON
DFLT_NSTART                            = 1    # max number of simultaneous outstanding interactions to a given server
DFLT_DEFAULT_LEISURE                   = 5    # in s. For multicast request, pick backoff before responding in [0..Leisure]
DFLT_EXCHANGE_LIFETIME                 = 248  # lifetime of a message ID
DFLT_RESPONSE_TIMEOUT                  = 60   # delay for app-level response

# CoAP Message Types
TYPE_CON                               = 0
TYPE_NON                               = 1
TYPE_ACK                               = 2
TYPE_RST                               = 3
TYPE_ALL = [
    TYPE_CON,
    TYPE_NON,
    TYPE_ACK,
    TYPE_RST,
]

# CoAP Method Codes
METHOD_GET                             = 1
METHOD_POST                            = 2
METHOD_PUT                             = 3
METHOD_DELETE                          = 4
METHOD_ALL = [
    METHOD_GET,
    METHOD_POST,
    METHOD_PUT,
    METHOD_DELETE,
]

# CoAP Response Codes
COAP_RC_NONE                           = 0
COAP_RC_2_01_CREATED                   = 65
COAP_RC_2_02_DELETED                   = 66
COAP_RC_2_03_VALID                     = 67
COAP_RC_2_04_CHANGED                   = 68
COAP_RC_2_05_CONTENT                   = 69
COAP_RC_ALL_SUCCESS = [
    COAP_RC_2_01_CREATED,
    COAP_RC_2_02_DELETED,
    COAP_RC_2_03_VALID,
    COAP_RC_2_04_CHANGED,
    COAP_RC_2_05_CONTENT,
]
COAP_RC_4_00_BADREQUEST                = 128
COAP_RC_4_01_UNAUTHORIZED              = 129
COAP_RC_4_02_BADOPTION                 = 130
COAP_RC_4_03_FORBIDDEN                 = 131
COAP_RC_4_04_NOTFOUND                  = 132
COAP_RC_4_05_METHODNOTALLOWED          = 133
COAP_RC_4_06_NOTACCEPTABLE             = 134
COAP_RC_4_12_PRECONDITIONFAILED        = 140
COAP_RC_4_13_REQUESTENTITYTOOLARGE     = 141
COAP_RC_4_15_UNSUPPORTEDCONTENTFORMAT  = 143
COAP_RC_ALL_ERROR_CLIENT = [
    COAP_RC_4_00_BADREQUEST,
    COAP_RC_4_01_UNAUTHORIZED,
    COAP_RC_4_02_BADOPTION,
    COAP_RC_4_03_FORBIDDEN,
    COAP_RC_4_04_NOTFOUND,
    COAP_RC_4_05_METHODNOTALLOWED,
    COAP_RC_4_06_NOTACCEPTABLE,
    COAP_RC_4_12_PRECONDITIONFAILED,
    COAP_RC_4_13_REQUESTENTITYTOOLARGE,
    COAP_RC_4_15_UNSUPPORTEDCONTENTFORMAT,
]
COAP_RC_5_00_INTERNALSERVERERROR       = 160
COAP_RC_5_01_NOTIMPLEMENTED            = 161
COAP_RC_5_02_BADGATEWAY                = 162
COAP_RC_5_03_SERVICEUNAVAILABLE        = 163
COAP_RC_5_04_GATEWAYTIMEOUT            = 164
COAP_RC_5_05_PROXYINGNOTSUPPORTED      = 165
COAP_RC_ALL_ERROR_SERVER = [
    COAP_RC_5_00_INTERNALSERVERERROR,
    COAP_RC_5_01_NOTIMPLEMENTED,
    COAP_RC_5_02_BADGATEWAY,
    COAP_RC_5_03_SERVICEUNAVAILABLE,
    COAP_RC_5_04_GATEWAYTIMEOUT,
    COAP_RC_5_05_PROXYINGNOTSUPPORTED,
]
COAP_RC_ALL_ERROR = COAP_RC_ALL_ERROR_CLIENT + \
                    COAP_RC_ALL_ERROR_SERVER
COAP_RC_ALL =       COAP_RC_ALL_SUCCESS + \
                    COAP_RC_ALL_ERROR

# CoAP Option Number Registry
OPTION_NUM_IFMATCH                     = 1
OPTION_NUM_URIHOST                     = 3
OPTION_NUM_ETAG                        = 4
OPTION_NUM_IFNONEMATCH                 = 5
OPTION_NUM_URIPORT                     = 7
OPTION_NUM_LOCATIONPATH                = 8
OPTION_NUM_URIPATH                     = 11
OPTION_NUM_CONTENTFORMAT               = 12
OPTION_NUM_MAXAGE                      = 14
OPTION_NUM_URIQUERY                    = 15
OPTION_NUM_ACCEPT                      = 17
OPTION_NUM_LOCATIONQUERY               = 20
OPTION_NUM_BLOCK2                      = 23
OPTION_NUM_BLOCK1                      = 27
OPTION_NUM_PROXYURI                    = 35
OPTION_NUM_PROXYSCHEME                 = 39
OPTION_NUM_OBJECT_SECURITY             = 21 # plugtest value
OPTION_NUM_STATELESSPROXY              = 40 # experimental value
OPTION_NUM_ALL = [
    OPTION_NUM_IFMATCH,
    OPTION_NUM_URIHOST,
    OPTION_NUM_ETAG,
    OPTION_NUM_IFNONEMATCH,
    OPTION_NUM_URIPORT,
    OPTION_NUM_LOCATIONPATH,
    OPTION_NUM_URIPATH,
    OPTION_NUM_CONTENTFORMAT,
    OPTION_NUM_MAXAGE,
    OPTION_NUM_URIQUERY,
    OPTION_NUM_ACCEPT,
    OPTION_NUM_LOCATIONQUERY,
    OPTION_NUM_BLOCK2,
    OPTION_NUM_BLOCK1,
    OPTION_NUM_PROXYURI,
    OPTION_NUM_PROXYSCHEME,
    OPTION_NUM_OBJECT_SECURITY,
    OPTION_NUM_STATELESSPROXY,
]

# CoAP Content-Format Registry
FORMAT_TEXTPLAIN                       = 0
FORMAT_LINKFORMAT                      = 40
FORMAT_XML                             = 41
FORMAT_OCTETSTREAM                     = 42
FORMAT_EXI                             = 47
FORMAT_JSON                            = 50
FORMAT_CBOR                            = 60
FORMAT_ALL = [
    FORMAT_TEXTPLAIN,
    FORMAT_LINKFORMAT,
    FORMAT_XML,
    FORMAT_OCTETSTREAM,
    FORMAT_EXI,
    FORMAT_JSON,
    FORMAT_CBOR,
]

# COSE defines for AES-CCM algorithm used in OSCoAP (c.f. draft-ietf-cose-msg-24)
COSE_AES_CCM_16_64_128                 = 10
COSE_AES_CCM_16_64_256                 = 11
COSE_AES_CCM_64_64_128                 = 12
COSE_AES_CCM_64_64_256                 = 13
COSE_AES_CCM_16_128_128                = 30
COSE_AES_CCM_16_128_256                = 31
COSE_AES_CCM_64_128_128                = 32
COSE_AES_CCM_64_128_256                = 33
COSE_AES_CCM_ALL = [
    COSE_AES_CCM_16_64_128,
    COSE_AES_CCM_16_64_256,
    COSE_AES_CCM_64_64_128,
    COSE_AES_CCM_64_64_256,
    COSE_AES_CCM_16_128_128,
    COSE_AES_CCM_16_128_256,
    COSE_AES_CCM_64_128_128,
    COSE_AES_CCM_64_128_256,
]
