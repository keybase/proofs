
{Base} = require './base'
{constants} = require './constants'
{Subkey,SubkeyBase} = require './subkey'
{stellar} = require 'bitcoyne'
assert = require 'assert'
pgp_utils = require('pgp-utils')
{bufeq_secure} = pgp_utils.util
{make_esc} = require 'iced-error'

#==========================================================================

km_to_base = (k) -> k.get_ekid()[2...-1]

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
    wallet_address = stellar.public_key.encode km_to_base @wallet.km
    assert stellar.public_key.is_valid wallet_address
    ret.body.wallet =
      network : @wallet.network
      name : @wallet.name
      address : wallet_address

  reverse_sig_check : ({json, new_km, subkm}, cb) ->
    esc = make_esc cb, "reverse_sig_check"
    await super { json, new_km, subkm }, esc defer()
    unless (a = json?.body?.wallet?.address)?
      err = new Error "didn't find a needed Stellar wallet address"
    else
      base_stellar = stellar.public_key.decode a
      base_kb = km_to_base new_km
      unless bufeq_secure base_stellar, base_kb
        err = new Error "Stellar Account ID didn't match given KID"
    cb err

  _required_sections : () -> super().concat(["wallet", "wallet_key"])
  _optional_sections : () -> super().concat(["revoke"])

  constructor : (obj) ->
    @wallet = obj.wallet
    super obj

#==========================================================================
