kbpgp = require 'kbpgp'
constants = require './constants'
KCP = kbpgp.const.openpgp
{akatch,bufeq_secure,json_stringify_sorted,unix_time,base64u} = kbpgp.util
triplesec = require('triplesec')
{WordArray} = triplesec
{SHA256} = triplesec.hash
{Message} = kbpgp.processor
{decode} = kbpgp.armor

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

  constructor : ({@pgp, @id, @short_id}, @km, @base) ->

  #---------------

  verify : (cb) ->
    esc = make_err cb, "Verifier::verfiy"
    await @_check_ids esc defer()
    await @_check_expired esc defer()
    await @_parse_and_process esc defer()
    await @_check_json esc defer ret
    cb null, ret

  #---------------

  _check_ids : (cb) ->
    {short_id, id} = make_ids @pgp
    err = if not bufeq_secure id, @id
      new Error "Long IDs aren't equal; wanted #{id} but got #{@id}"
    else if not bufeq_secure short_id, @short_id
      new Error "Short IDs aren't equal: wanted #{short_id} but got #{@short_id}"
    else null
    cb err

  #---------------

  _check_expired : (cb) ->
    now = unix_time()
    expired = (now - json.date - json.expire_in)
    err = if expired > 0 then new Error "Expired #{expired}s ago"
    else null
    cb err

  #---------------

  _parse_and_process : (cb) ->
    esc = make_err cb, "Verifier::_parse_and_process"
    err = null
    await akatch (() -> decode @pgp), esc defer msg
    if msg.type isnt KCP.message_types.generic
      err = new Error "wrong mesasge type; expected a generic message"
    else
      eng = new Message @km
      await end.parse_and_process msg.body, esc defer @literals
    cb err

  #---------------

  _check_json : (cb) -> 
    err = json = null
    if (n = @literals.length) isnt 1
      err = new Error "Expected only one pgp literal; got #{n}"
    else 
      try
        json = JSON.parse (l = @literals[0]).data
        await @base._v_check {json}, esc defer()
        if not (sw = l.signed_with)?
          err = new Error "Expected a signature on the payload message"
        else if not bufeq_secure @km.get_pgp_key_id(), sw.get_key_id()
          err = new Error "Key in signature packet didn't match"
      catch e
        err = new Error "Couldn't parse JSON signed message: #{e.message}"
    cb err, json

#==========================================================================

class Base

  #------

  constructor : ({@km}) ->

  #------

  _v_check : (obj, cb) -> cb null

  #------

  json : ({tag, expire_in, body, seqno}) ->
    expire_in or= constants.expire_in
    tag  = constants.tags.sig
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
    verifier = new Verifier obj, @km, @
    await verifier.verify esc defer ret
    cb null, ret

#==========================================================================

exports.Base = Base

#==========================================================================

