
parse = require './parse3'

mkerr = (path, err) -> new Error "At #{path.toString()}: #{err}"

class Path
  constructor : (v) ->
    @_v = v or []
  extend : (e) -> new Path @_v.concat [e]
  toString : () -> @_v.join(".")
  @top : (n) -> new Path [ n or "<top>" ]

class Node
  constructor : ({}) ->
    @_optional = false
    @_convert = false
    @_name = ""
    @_path = []
  optional : () ->
    @_optional = true
    @
  is_optional : () -> @_optional
  convert : () ->
    @_convert = true
    @
  name : (n) ->
    @_name = n
    @
  _check : ({path, obj}) -> mkerr path, "internal error, no checker found"

  check : (obj) -> @_check { path : Path.top(@_name), obj }

  _check_value : ({checker, path, obj}) ->
    if not obj? and checker.is_optional() then return null
    if not obj? then mkerr path, "value cannot be null"
    return checker._check { path, obj  }

class Dict extends Node
  constructor : ({keys}) ->
    @_keys = keys
    super

  _check : ({path, obj}) ->
    if not parse.is_dict(obj)
      return mkerr path, "need a dictionary"
    for k,v of obj
      new_path = path.extend(k)
      if not (checker = @_keys[k])? then return mkerr new_path, "key is not supported"
      if (err = @_check_value { checker, path : new_path, obj : v }) then return err
    for k,v of @_keys
      new_path = path.extend(k)
      if not obj[k]? and not v.is_optional() then return mkerr new_path, "key is missing but is mandatory"
    return null

  set_key : (k,v) ->
    @_keys[k] = v

class Array extends Node

  constructor : ({slots}) ->
    @_slots = slots

  _check : ({path, obj}) ->
    unless parse.is_array(obj)
      return mkerr path, "need an array"
    if obj.length isnt @_slots.length
      return mkerr path, "need an array with #{@_slots.length} fields"
    for o,i in obj
      new_path = path.extend(i.toString())
      if (err = @_check_value { checker : @_slots[i], path : new_path, obj : o  }) then return err
    return null

class Binary extends Node

  constructor : ({len}) ->
    @_len = len

  _check : ({path, obj}) ->
    if @_convert and typeof(obj) is 'string'
      obj = Buffer.from(obj, 'hex')
    unless Buffer.isBuffer(obj) and obj.length is @_len
      return mkerr path, "value needs to be buffer of length #{@_len}"
    return null

class KID extends Binary

  constructor : ({encryption}) ->
    @_encryption = encryption
    @_len = 35

  _check : ({path, obj}) ->
    return err if (err = super { path, obj })?
    typ = if @_encryption then 0x21 else 0x20
    if obj[0] isnt 0x01 or obj[1] isnt typ or obj[-1...][0] isnt 0x0a
      return mkerr path, "value must be a KID#{if @_encryption then ' (for encryption)' else ''}"
    return null

class Seqno extends Node
  _check : ({path, obj}) ->
    if not parse.is_seqno obj then return mkerr path, "value must be a seqno (sequence number)"
    return null

class Int extends Node
  _check : ({path, obj}) ->
    if not parse.is_int obj then return mkerr path, "value must be an int"
    return null

class Time extends Node
  _check : ({path, obj}) ->
    if not parse.is_time obj then return mkerr path, "value must be a UTC timestamp"
    return null

class ChainType extends Node
  _check : ({path, obj}) ->
    if not parse.is_chain_type obj then return mkerr path, "value must be a valid chain type"
    return null

class String extends Node
  _check : ({path, obj}) ->
    if typeof(obj) isnt 'string' or obj.length is 0 then return mkerr path, "value must be a string"
    return null

class Value extends Node
  constructor : (@_value) ->
  _check : ({path, obj}) ->
    unless obj is @_value then return mkerr path, "must be set to value #{@_value}"
    return null

class LinkType extends Node
  _check : ({path, obj}) ->
    if not parse.is_link_type obj then return mkerr path, "value must be a valid link type"
    return null

class Bool extends Node
  _check : ({path, obj}) ->
    if not parse.is_bool obj then return mkerr path, "value must be a boolean"
    return null

class Object extends Node
  _check : ({path, obj}) -> null

exports.dict = (keys) -> new Dict { keys }
exports.binary = (l) -> new Binary { len : l }
exports.uid = () -> new Binary { len : 16 }
exports.kid = () -> new KID { encryption : false }
exports.enc_kid = () -> new KID { encryption : true }
exports.seqno = () -> new Seqno {}
exports.time = () -> new Time {}
exports.int = () -> new Int {}
exports.uid = () -> new Binary { len : 16 }
exports.chain_type = () -> new ChainType {}
exports.link_type = () -> new LinkType {}
exports.string = () -> new String {}
exports.value = (v) -> new Value v
exports.bool = () -> new Bool {}
exports.array = (s) -> new Array {slots : s}
exports.obj = () -> new Object {}
