
{Base} = require './base'
{constants} = require './constants'
{Subkey,SubkeyBase} = require './subkey'
{stellar} = require 'bitcoyne'
assert = require 'assert'

#==========================================================================

exports.Wallet = class Wallet extends SubkeyBase

  get_key_field : () -> "wallet_key"
  get_new_key_section : () -> @wallet_key
  set_new_key_section : (m) -> @wallet_key = m
  get_new_km : () -> @wallet.km
  _type : () -> constants.sig_types.wallet
  _type_v2 : () -> constants.sig_types_v2.wallet
  need_reverse_sig : () -> true

  _v_customize_json : (ret) ->
    super ret
    wallet_address = stellar.public_key.encode @wallet.km.get_ekid()[2...-1]
    assert stellar.public_key.is_valid wallet_address
    ret.body.wallet =
      network : @wallet.network
      name : @wallet.name
      address : wallet_address

  _required_sections : () -> super().concat(["wallet", "wallet_key"])
  _optional_sections : () -> super().concat(["revoke"])

  constructor : (obj) ->
    @wallet = obj.wallet
    super obj

#==========================================================================
