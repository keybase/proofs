
{Base} = require './base'
{constants} = require './constants'
{SubkeyBase} = require './subkey'

#==========================================================================

exports.SharedDHKey = class SharedDHKey extends SubkeyBase

  get_field : () -> "shared_dh_key"
  get_new_key_section : () -> @shared_dh_key
  set_new_key_section : (m) -> @shared_dh_key = m
  get_new_km : () -> @shared_dh_km
  _type : () -> constants.sig_types.shared_dh_key
  _type_v2 : () -> constants.sig_types_v2.shared_dh_key

  _v_include_pgp_details : () -> true
  _required_sections : () -> super().concat(["shared_dh_key"])
  _v_check : ({json}, cb) ->
    err = null
    if typeof (v = json?.body?.shared_dh_key?.generation) isnt 'number'
      err = new Error "Need shared_dh_key.generation to be an integer"
    else
      await super { json }, defer err
    cb err

  constructor : (obj) ->
    @shared_dh_key = obj.shared_dh_key
    @shared_dh_km  = obj.shared_dh_km
    super obj

#==========================================================================
