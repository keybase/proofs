kbpgp = require 'kbpgp'
constants = require './constants'
KCP = kbpgp.const.openpgp
{json_stringify_sorted,unix_time,base64u} = kbpgp.util
triplesec = require('triplesec')
{WordArray} = triplesec
{SHA256} = triplesec.hash
{Message} = kbpgp.processor

#==========================================================================

class Verifier 

  constructor : ({@pgp, @json, @id, @short_id}, @km) ->

  verify : (cb) ->
    esc = make_err cb, "Verifier::verfiy"
    await @_check_ids esc defer()
    await @_check_expired esc defer()
    await @_parse_and_process esc defer()
    await @_check_json esc defer()

#==========================================================================

class Base

  #------

  constructor : ({@km}) ->

  #------

  hash : (pgp) -> (SHA256.transform(WordArray.from_utf8 pgp)).to_buffer()

  #------

  _v_check : (cb) -> cb null

  #------

  json : ({tag, expire_in, body, seqno}) ->
    expire_in or= constants.expire_in
    tag  = constants.tags.sig,
    date = unix_time()
    out  = { tag, expire_in, body, date }
    out.seqno = seqno if seqno?
    out

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

  #------

  verify : (obj, cb) ->
    esc = make_err cb, "Base::verfiy"
    verifier = new Verifier obj, @km
    await @_v_check obj, esc defer()
    await verifier.verify esc defer()
    cb null

#==========================================================================

exports.Base = Base

#==========================================================================

