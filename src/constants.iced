
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
    FAILED_LOAD:      1
    UNEXPECTED_PARSE: 2
    CONTENT_FAILURE:  3
    TEXT_NOT_FOUND:   4
    NOT_PUBLIC:       5
