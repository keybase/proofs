kbpgp = require 'kbpgp'
constants = require './constants'
KCP = kbpgp.const.openpgp
{bufeq_secure,json_stringify_sorted,unix_time,base64u} = kbpgp.util
triplesec = require('triplesec')
{WordArray} = triplesec
{SHA256} = triplesec.hash
{Message} = kbpgp.processor

#==========================================================================

sha256 = (pgp) -> (SHA256.transform(WordArray.from_utf8 pgp)).to_buffer()

#------

make_ids = (pgp) ->
  hash = sha256 pgp
  id = hash.to_hex()
  short_id = base64u.encode hash[0...constants.short_id_bytes]
  { id, short_id }

#==========================================================================

class Verifier 

  constructor : ({@pgp, @json, @id, @short_id}, @km) ->

  verify : (cb) ->
    esc = make_err cb, "Verifier::verfiy"
    await @_check_ids esc defer()
    await @_check_expired esc defer()
    await @_parse_and_process esc defer()
    await @_check_json esc defer()

  _check_ids : (cb) ->
    {short_id, id} = make_ids @pgp
    err = if not bufeq_secure short_id, @short_id
      new Error "Short IDs aren't equal: wanted #{short_id} but got #{@short_id}"
    else if not bufeq_secure id, @id
      new Error "Long IDs aren't equal; wanted #{id} but got #{@id}"
    else null
    cb err

#==========================================================================

class Base

  #------

  constructor : ({@km}) ->

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
        {short_id, id} = make_ids pgp
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

