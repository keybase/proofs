
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

  constructor : (obj) ->
    @sibkey = obj.sibkey
    @sibkm = obj.sibkm
    super obj

#==========================================================================

exports.Dualkey = class Dualkey extends Base

  constructor : (obj) ->
    @sibkey = new Sibkey obj
    @subkey = new Subkey obj

  _v_check : ({json}, cb) ->
    err = null
    await @sibkey._v_check { json }, defer err
    await @subkey._v_check { json }, defer err unless err?
    cb null

#==========================================================================
