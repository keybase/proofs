
{Base} = require './base'
{constants} = require './constants'
{Subkey,SubkeyBase} = require './subkey'

#==========================================================================

exports.Sibkey = class Sibkey extends SubkeyBase

  get_field : () -> "sibkey"
  get_subkey : () -> @sibkey
  get_subkm : () -> @sibkm
  set_subkey : (s) -> @sibkey = s
  _type : () -> constants.sig_types.sibkey
  need_reverse_sig : () -> true

  _required_sections : () -> super().concat(["sibkey"])

  constructor : (obj) ->
    @sibkey = obj.sibkey
    @sibkm = obj.sibkm
    super obj

#==========================================================================

exports.Dualkey = class Dualkey extends Base

  _required_sections : () -> super().concat(["sibkey", "subkey"])

  constructor : (obj) ->
    @sibkey = new Sibkey obj
    @subkey = new Subkey obj
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.dualkey

  _json : () ->
    ret = super {}
    ret.body.device = @device
    sib = @sibkey._json()
    sub = @subkey._json()
    ret.body.subkey = sub.body.subkey
    ret.body.sibkey = sib.body.sibkey
    return ret

  _v_generate : (args, cb) ->
    await @sibkey._v_generate args, defer err
    await @subkey._v_generate args, defer err2
    cb (err or err2)

  _v_check : ({json}, cb) ->
    err = null
    await @sibkey._v_check { json }, defer err
    await @subkey._v_check { json }, defer err unless err?
    cb null

#==========================================================================
