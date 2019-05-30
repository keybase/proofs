{unpack} = require 'purepack'
{constants} = require './constants'
{pack} = require './util'
{bufeq_fast} = require('pgp-utils').util

#=======================================================

exports.is_dict = is_dict = (o) -> typeof(o) is 'object' and not Array.isArray(o) and o?
exports.is_array = (o) -> typeof(o) is 'object' and Array.isArray(o)
exports.is_string = (s) -> typeof(s) is 'string' and s.length > 0
exports.is_uid = (u) -> is_hex(u, 16)
exports.is_prev = (p) -> not(p?) or is_hex(p, 32)
exports.is_inner_link_hash = (h) -> is_hex(h, 32)
exports.is_kid = (h) -> is_hex(h,35)
exports.is_int = is_int = (s) ->
    n = Math.floor Number s
    return typeof(s) is 'number' and (n isnt Infinity) and (n is s) and n >= 0
exports.is_hex = is_hex = (h, l) ->
  return false unless h?
  if typeof(h) is 'string' then h = Buffer.from(h, 'hex')
  else if not Buffer.isBuffer then return false
  return (h.length is l)
exports.is_seqno = (s) ->
  return false unless s?
  return false unless is_int s
  return false unless s >= 0 and s <= 99999999
  return true
exports.is_bool = (b) -> typeof(b) is 'boolean'
exports.dearmor_dict = (armored) ->
  if not is_dict(armored) then throw new Error "need an object of encodings"
  ret = {}
  for k,v of armored
    raw = Buffer.from(v, 'base64')
    if raw.toString('base64') isnt v then throw new Error "non-canonical base64-encoding in #{k}"
    ret[k] = raw
  return ret

exports.unpack_dict = (raw) ->
  if not is_dict(raw) then throw new Error "need an object of packed objects"
  ret = {}
  for k,v of raw
    ret[k] = unpack_strict v
  return ret

unpack_strict = (v) ->
  ret = unpack v
  expected = pack ret
  throw new Error("strict decoding requirement failed") unless bufeq_fast(v, expected)
  return ret

exports.is_link_type = (x) ->
  return false unless is_int x
  return false unless x in [constants.sig_types_v3.user.peg, constants.sig_types_v3.team.rotate_key]
  return true

exports.is_ptk_type = (x) ->
  return false unless is_int x
  return false unless x in [constants.ptk_types.reader]
  return true

exports.is_time = (x) ->
  return false unless is_int x
  return false unless x > 0
  return false unless x > 946702800
  return false unless x < 1893474000
  return true

exports.is_chain_type = (x) ->
  return false unless is_int x
  d = {}
  for _,v of constants.seq_types
    return true if v is x
  return false

exports.unhex = (b) ->
  if not b? then null
  else if Buffer.isBuffer(b) then b
  else if typeof(b) is 'string' then Buffer.from(b, 'hex')
  else throw new Error "bad binary or hex string"

