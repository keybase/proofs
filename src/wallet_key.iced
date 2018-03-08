
{Base} = require './base'
{constants} = require './constants'
{Subkey,SubkeyBase} = require './subkey'

#==========================================================================

exports.WalletKey = class WalletKey extends SubkeyBase

  get_key_field : () -> "wallet_key"
  get_new_key_section : () -> @wallet_key
  set_new_key_section : (m) ->
    m.kid = @wallet_km.get_ekid().toString('hex')
    m.currency = @currency
    @wallet_key = m
  get_new_km : () -> @wallet_km
  _type : () -> constants.sig_types.wallet_key
  _type_v2 : () -> constants.sig_types_v2.wallet_key
  need_reverse_sig : () -> true

  _v_include_pgp_details : () -> true
  _required_sections : () -> super().concat(["wallet_key"])
  _optional_sections : () -> super().concat(["revoke"])

  constructor : (obj) ->
    @wallet_km = obj.wallet.km
    @currency = obj.wallet.currency
    super obj

#==========================================================================
