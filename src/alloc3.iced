
{make_esc} = require 'iced-error'
{KeyManager} = require('kbpgp').kb
{constants} = require './constants'
{bufferify,sha256} = require './util'
pgp_utils = require('pgp-utils')
{bufeq_secure} = pgp_utils.util
parse = require './parse3'
{OuterLink} = require './sig3'
{RotateKey} = require './team_hidden'
{errors} = require './errors'
schema = require './schema3'

#=======================================================

_check_prev = (a,b) ->
  return null if not(a?) and not (b?)
  return (new errors.BadPrevError "null versus non-null in prev comparison") if not(a?) or not(b?)
  return (new errors.BadPrevError "hash mismatch in prevs") unless bufeq_secure(a,b)
  return null

_hex_to_buffer = (h) ->
  try
    return parse.unhex(h)
  catch
    return null

_uid_eq = (u1, u2) ->
  u1 = _hex_to_buffer u1
  u2 = _hex_to_buffer u2
  return u1? and u2? and bufeq_secure u1, u2

#=======================================================

_parse_inputs = ({armored, km, skip_inner, check_params}) ->

  errout = (e) -> [(new Error e), {}]

  if not armored? or not parse.is_dict armored
    return errout 'need a dictionary of armored, packed structs (inner and outer) and also a sig'

  try
    raw = parse.dearmor_dict armored
    json = parse.unpack_dict raw
  catch e
    return errout(e)

  if not json?.outer? or not json?.sig
    return errout "need 'outer' and 'sig' fields"

  if not parse.is_array json?.outer
    return errout "'outer' must be an array"

  if not Buffer.isBuffer(json.sig) or json.sig.length isnt 64
    return errout "'sig' must be a binary buffer (with a signature of 64 bytes)"

  unless skip_inner
    if not json?.inner?
      return errout "need 'inner' or an explicit skip_inner flag"
    if not parse.is_dict json.inner
      return errout "'inner' must be a dictionary"

  unless km?
    return errout "need non-null KeyManager km"

  unless check_params?
    return errout "need check_params"

  schm = schema.dict({
    user : schema.dict({
      local : schema.dict ({
        uid : schema.uid().name("uid").convert()
        eldest_seqno : schema.seqno().name("eldest_seqno") }) })
    prev : schema.binary(32).optional().name("prev").convert()
    seqno : schema.seqno().name("seqno")
  }).name("check_params")

  return [err, {}] if (err = schm.check check_params)?

  [ null, { json, raw } ]

#=======================================================

_verify_outer_sig = ({outer, sig, km}, cb) ->
  km.verify_raw { prefix : bufferify(constants.sig_prefixes[constants.versions.sig_v3]), payload : outer, sig }, cb

_verify_inner_hash = ({inner, outer_obj, km}, cb) ->
  cb (if bufeq_secure(outer_obj.inner_hash, sha256(inner)) then null else new Error "outer's body hash doesn't match inner link")

_parse_outer_link = ({array}, cb) -> cb (OuterLink.decode array)...

_check_inner = ({inner_obj, km, check_params}, cb) ->
  e = (m) -> new Error m
  c = ->
    return e("bad UID") unless _uid_eq inner_obj.user.local.uid, check_params.user.local.uid
    return e("bad eldest_seqno") unless inner_obj.user.local.eldest_seqno is check_params.user.local.eldest_seqno
    return e("bad key ID") unless bufeq_secure inner_obj.sig_eng.get_km().key.ekid(), km.key.ekid()
    return null
  cb c()

_check_chain = ({outer_obj, check_params}, cb) ->
  if (outer_obj.seqno isnt check_params.seqno) then err = new errors.WrongSeqno "bad sequence number in chain (#{outer_obj.seqno} != #{check_params.seqno})"
  else err = _check_prev outer_obj.prev, check_params.prev
  cb err

#=======================================================

_alloc_inner_obj = ({outer_obj, inner_json}, cb) ->
  esc = make_esc cb
  klass = switch outer_obj.link_type
    when constants.sig_types_v3.team.rotate_key then RotateKey
    else null
  if not klass?
    return cb new Error "no class for type #{outer_obj.link_type}"

  obj = new klass {}
  await obj.decode_inner { json : inner_json, outer_obj }, esc defer()

  cb null, obj

#=======================================================

#
# alloc_v3 allocates a v3 version of the object, given an armored object, which
# in turns has 3 fields:
#
#   * armored.inner - the base64 encoding of the inner link (as a msgpack dict)
#   * armored.outer - the base64 encoding of the outer link (as a msgpack array)
#   * armored.sig   - the base64 encoding of the 64-byte NaCl signature (without any additional packetizing fluff).
#
# You also need to pass input parameters to check against:
#
#   * check_params.user.local.uid - the UID we had in mind
#   * check_params.user.local.eldest_seqno - the eldest serqno of the user
#   * check_params.prev - the previous link ID expected in the chain
#   * check_params.seqno - the expected sequence number of this link in the chain.
#
# It will do all signature verifications against the given Key Manager (km), and will
# return an object that has:
#
#   * objs.inner  - an "object" wrapper of the inner proof
#   * objs.outer  - an "object" wrapper of the outer link
#   * json.inner  - a JSON representation of the inner object
#   * json.outer  - a JSON representation of the outer object
#
# If the signature verification failed, you'll get an error and no outputs.
#
# Specify `skip_inner : true` if you want the inner linked stubbed out. Otherwise, it
# will be an error.
#
alloc_v3 = ({armored, km, skip_inner, check_params, now}, cb) ->
  esc = make_esc cb
  [err, {json, raw}] = _parse_inputs { armored, km, check_params }
  if err? then return cb err
  await _verify_outer_sig { outer : raw.outer, sig : json.sig, km }, esc defer()
  objs = {}
  await _parse_outer_link {array : json.outer}, esc defer objs.outer
  await _check_chain { outer_obj : objs.outer, check_params }, esc defer()
  unless skip_inner
    await _verify_inner_hash { inner : raw.inner, outer_obj : objs.outer }, esc defer()
    await _alloc_inner_obj { outer_obj : objs.outer, inner_json : json.inner }, esc defer objs.inner
    await _check_inner { inner_obj : objs.inner, km, check_params }, esc defer()
    await objs.inner.check { now }, esc defer()
    await objs.inner.verify_reverse_sig { outer_obj : objs.outer, inner : json.inner }, esc defer()
  cb null, { objs, json }

#=======================================================

exports.alloc_v3 = alloc_v3

#=======================================================
