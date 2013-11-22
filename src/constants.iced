
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
    BASE_ERROR:        100
    HOST_UNREACHABLE:  101
    PERMISSION_DENIED: 103 # Since the user might fix it
    FAILED_PARSE:      106
    HTTP_500:          150

    # Likely will result in a hard error, if repeated enough
    BASE_HARD_ERROR:   200
    NOT_FOUND:         201
    CONTENT_FAILURE:   202
    HTTP_300:          130
    HTTP_400:          140
    HTTP_OTHER:        160

    # Hard final errors
    DELETED:           301
    SERVICE_DEAD:      302
    BAD_SIGNATURE:     303
