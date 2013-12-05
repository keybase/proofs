
exports.constants = constants = 
  tags :
    sig : "signature"
  versions :
    sig : 1
  sig_types :
    web_service_binding : "web_service_binding"
    track : "track"
  proof_types :
    none : 0
    keybase : 1
    twitter : 2
    github : 3
  expire_in : 60*60*24*365*5 # 5 years....
  short_id_bytes : 27

d = {}
(d[v] = k for k,v of constants.proof_types)
exports.proof_type_to_string = d
