
exports.constants = 
  tags :
    sig : "signature"
  versions :
    sig : 1
  sig_types :
    web_service_binding : "web_service_binding"
  proof_types :
    none : 0
    keybase : 1
    twitter : 2
  expire_in : 60*60*24*365*5 # 5 years....
  short_id_bytes : 27
  v_codes:
    NONE:              0
    OK:                1
    LOCAL:             2
    FOUND:             3 # It's been found in the hunt, but not proven yet
    # Retryable soft errors
    HOST_UNREACHABLE:  101
    HTTP_NON_200:      102
    PERMISSION_DENIED: 103
    NOT_FOUND:         104
    CONTENT_FAILURE:   105
    FAILED_PARSE:      106
    # Hard final errors
    DELETED:           201
    SERVICE_DEAD:      202
    BAD_SIGNATURE:     203
