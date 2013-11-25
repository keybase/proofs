kbpgp = require 'kbpgp'
{constants} = require './constants'
KCP = kbpgp.const.openpgp
{katch,akatch,bufeq_secure,json_stringify_sorted,unix_time,base64u,streq_secure} = kbpgp.util
triplesec = require('triplesec')
{WordArray} = triplesec
{SHA256} = triplesec.hash
{Message} = kbpgp.processor
{decode} = kbpgp.armor
{make_esc} = require 'iced-error'
util = require 'util'

#==========================================================================

sha256 = (pgp) -> (new SHA256).bufhash(new Buffer pgp, 'utf8')

#------

add_ids = (pgp, out) ->
  hash = sha256 pgp
  id = hash.toString('hex')
  short_id = sig_id_to_short_id hash
  out.id = id
  out.short_id = short_id

#------

make_ids = (pgp) -> 
  out = {}
  add_ids pgp, out
  return out

#------

sig_id_to_short_id = (sig_id) ->
  base64u.encode sig_id[0...constants.short_id_bytes]

#==========================================================================

class Verifier 

  constructor : ({@pgp, @id, @short_id}, @km, @base) ->

  #---------------

  verify : (cb) ->
    esc = make_esc cb, "Verifier::verfiy"
    await @_check_ids esc defer()
    await @_parse_and_process esc defer()
    await @_check_json esc defer ret
    await @_check_expired esc defer()
    cb null, ret

  #---------------

  _check_ids : (cb) ->
    {short_id, id} = make_ids @pgp
    err = if not streq_secure id, @id
      new Error "Long IDs aren't equal; wanted #{id} but got #{@id}"
    else if not streq_secure short_id, @short_id
      new Error "Short IDs aren't equal: wanted #{short_id} but got #{@short_id}"
    else null
    cb err

  #---------------

  _check_expired : (cb) ->
    now = unix_time()
    expired = (now - @json.date - @json.expire_in)
    err = if expired > 0 then new Error "Expired #{expired}s ago"
    else null
    cb err

  #---------------

  _parse_and_process : (cb) ->
    err = null
    [ err, msg] = decode @pgp
    if not err? and (msg.type isnt KCP.message_types.generic)
      err = new Error "wrong mesasge type; expected a generic message; got #{msg.type}"
    if not err?
      eng = new Message @km
      await eng.parse_and_process msg.body, defer err, @literals
    cb err

  #---------------

  _check_json : (cb) -> 
    err = json = null
    if (n = @literals.length) isnt 1
      err = new Error "Expected only one pgp literal; got #{n}"
    else 
      l = @literals[0]
      [e, @json] = katch (() -> JSON.parse l.data)
      err = new Error "Couldn't parse JSON signed message: #{e.message}" if e?
    if not err?
      await @base._v_check {@json}, defer err
      if err? then #noop
      else if not (sw = l.get_data_signer()?.sig)?
        err = new Error "Expected a signature on the payload message"
      else if not (@km.find_pgp_key (b = sw.get_key_id()))?
        err = new Error "Failed sanity check; didn't have a key for '#{b.toString('hex')}'"
    cb err, @json

#==========================================================================

class Base

  #------

  constructor : ({@km}) ->

  #------

  _v_check : (obj, cb) -> cb null

  #------

  is_remote_proof : () -> true

  #------


  _json : ({tag, expire_in, body, seqno}) ->
    expire_in or= constants.expire_in
    tag  = constants.tags.sig
    date = unix_time()
    out  = { tag, expire_in, body, date }
    out.seqno = seqno if seqno?
    out

  #------

  json : -> json_stringify_sorted @_json()

  #------

  generate : (cb) ->
    out = null
    json = @json()
    if not (signing_key = @km.find_best_pgp_key KCP.key_flags.sign_data)?
      err = new Error "No signing key found"
    else
      await kbpgp.burn { msg : json, signing_key, armor : true  }, defer err, pgp
      unless err?
        {short_id, id} = make_ids pgp
        out = { pgp, json, id, short_id }
    cb err, out

  #------

  # @param {Object} obj with options as specified:
  # @option obj {string} pgp The PGP signature that's being uploaded
  # @option obj {string} id The keybase-appropriate ID that's the PGP signature's hash
  # @option obj {string} short_id The shortened sig ID that's for the tweet (or similar)
  verify : (obj, cb) ->
    esc = make_esc cb, "Base::verfiy"
    verifier = new Verifier obj, @km, @
    await verifier.verify esc defer ret
    cb null, ret

#==========================================================================

exports.Base = Base
exports.sig_id_to_short_id = sig_id_to_short_id
exports.make_ids = make_ids
exports.add_ids = add_ids

#==========================================================================

