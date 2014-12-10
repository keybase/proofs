
{Base} = require './base'
{constants} = require './constants'
{make_esc} = require 'iced-error'

#==========================================================================

exports.SubkeyBase = class SubkeyBase extends Base

  get_subkey : () -> null
  get_subkm : () -> null
  set_subkey : (s) ->
  get_field : () -> null

  _v_generate : (opts, cb) ->
    esc = make_esc cb, "_v_generate"
    if not @get_subkey()? and @get_subkey()?
      eng = @get_subkm().make_sig_eng()
      msg = @km.get_ekid().toString('hex')
      await eng.box msg, esc defer { armored, type }
      obj =
        kid : @get_subkm().get_ekid().toString('hex')
        reverse_sig:
          sig : armored
          type : type
      @set_subkey obj
    cb null

  _json : () ->
    ret = super {}
    ret.body[@get_field()] = @get_subkey()
    return ret

#==========================================================================

exports.Subkey = class Subkey extends SubkeyBase

  get_field : () -> "subkey"
  get_subkey : () -> @subkey
  get_subkm : () -> @subkm
  set_subkey : (s) -> @subkey = s
  _type : () -> constants.sig_types.subkey

  constructor : (obj) ->
    @subkey = obj.subkey
    @subkm = obj.subkm
    super obj

#==========================================================================
