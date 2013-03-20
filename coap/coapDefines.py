DEFAULT_UDP_PORT                       = 5683
COAP_SCHEME                            = 'coap://'

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
OPTION_NUM_ACCEPT                      = 16
OPTION_NUM_LOCATIONQUERY               = 20
OPTION_NUM_PROXYURI                    = 35
OPTION_NUM_PROXYSCHEME                 = 39

# CoAP Content-Format Registry
FORMAT_TEXTPLAIN                       = 0
FORMAT_LINKFORMAT                      = 40
FORMAT_XML                             = 41
FORMAT_OCTETSTREAM                     = 42
FORMAT_EXI                             = 47
FORMAT_JSON                            = 50
FORMAT_ALL = [
    FORMAT_TEXTPLAIN,
    FORMAT_LINKFORMAT,
    FORMAT_XML,
    FORMAT_OCTETSTREAM,
    FORMAT_EXI,
    FORMAT_JSON,
]
