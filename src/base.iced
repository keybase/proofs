kbpgp = require 'kbpgp'
constants = require './constants'
KCP = kbpgp.const.openpgp
{json_stringify_sorted,unix_time,base64u} = kbpgp.util
triplesec = require('triplesec')
{WordArray} = triplesec
{SHA256} = triplesec.hash

#==========================================================================

class Base

  #------

  constructor : ({@km}) ->

  #------

  hash : (pgp) -> (SHA256.transform(WordArray.from_utf8 pgp)).to_buffer()

  #------

  generate : (cb) ->
    out = null
    json = json_stringify_sorted @json()
    if not (signing_key = @km.find_best_pgp_key KCP.key_flags.sign_data)?
      err = new Error "No signing key found"
    else
      await kbpgp.burn { msg : json, signing_key, armor : true  }, defer err, pgp
      unless err?
        hash = @hash pgp
        id = hash.to_hex()
        short_id = base64u.encode hash[0...constants.short_id_bytes]
        out = { pgp, json, id, short_id }
    cb err, out

#==========================================================================

exports.Base = Base

#==========================================================================

