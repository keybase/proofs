
{Base} = require './base'
{constants} = require './constants'
{SubkeyBase} = require './subkey'

#==========================================================================

exports.Masterkey = class Masterkey extends SubkeyBase

  get_field : () -> "masterkey"
  get_new_key_section : () -> @masterkey
  set_new_key_section : (m) -> @masterkey = m
  get_new_km : () -> @masterkm
  _type : () -> constants.sig_types.masterkey
  _type_v2 : () -> constants.sig_types_v2.masterkey
  need_reverse_sig : () -> true

  _v_include_pgp_details : () -> true
  _required_sections : () -> super().concat(["masterkey"])

  constructor : (obj) ->
    @masterkey = obj.masterkey
    @masterkm  = obj.masterkm
    super obj

#==========================================================================
