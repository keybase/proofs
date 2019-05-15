{constants} = require './constants'
{json_stringify_sorted,bufeq_secure} = require('pgp-utils').util
crypto = require 'crypto'
{pack} = require 'purepack'

#----------

exports.json_secure_compare = json_secure_compare = (a,b) ->
  [o1,o2] = (json_stringify_sorted(x) for x in [a,b])
  err = if bufeq_secure((Buffer.from o1, 'utf8'), (Buffer.from o2, 'utf8')) then null
  else new Error "Json objects differed: #{o1} != #{o2}"
  return err

##-----------------------------------------------------------------------

exports.v2_sig_type_from_sig_type = v2_sig_type_from_sig_type = (type) ->
  # parse out the v2 sig type from a string. i.e. "team.settings -> 46
  keys = type.split(".")
  v = constants.sig_types_v2
  for k in keys
    v = v[k]
  return v

##-----------------------------------------------------------------------

exports.bufferify = (b) -> if Buffer.isBuffer(b) then b else (Buffer.from b, 'utf8')

##-----------------------------------------------------------------------

# Copied from iced-utils, so as not to introduce a dependency
# on a library that's used mainly in node.
exports.Lock = class Lock
  constructor : ->
    @_open = true
    @_waiters = []
  acquire : (cb) ->
    if @_open
      @_open = false
      cb()
    else
      @_waiters.push cb
  release : ->
    if @_waiters.length
      w = @_waiters.shift()
      w()
    else
      @_open = true
  open : -> @_open

##-----------------------------------------------------------------------

exports.space_normalize = (s) -> s.split(/[\r\n\t ]+/).join(' ')

##-----------------------------------------------------------------------

exports.sha256 = (b) -> crypto.createHash('SHA256').update(b).digest('buffer')

##-----------------------------------------------------------------------

exports.pack = (o) -> pack o, { sort_keys : true }

##-----------------------------------------------------------------------

