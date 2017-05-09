
{Base} = require './base'
{constants} = require './constants'
{SubkeyBase} = require './subkey'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'

#==========================================================================

exports.PerUserKey = class PerUserKey extends SubkeyBase

  get_key_field : () -> "per_user_key"
  get_new_key_section : () -> @per_user_key
  set_new_key_section : (m) ->
    m.generation = @generation
    m.encryption_kid = @kms.encryption.get_ekid().toString('hex')
    @per_user_key = m
  get_new_km : () -> @kms.signing # use the signing KM
  sibkid_slot : () -> "signing_kid"
  _type : () -> constants.sig_types.per_user_key
  _type_v2 : () -> constants.sig_types_v2.per_user_key

  _v_include_pgp_details : () -> false
  _required_sections : () -> super().concat(["per_user_key"])

  _find_fields : ({json}) ->
    if (typeof(v = json?.body?.per_user_key?.generation) isnt 'number') or (parseInt(v) <= 0)
      new Error "Need per_user_key.generation to be an integer > 0 (got #{v})"
    else if not json?.body?.per_user_key?.signing_kid?
      new Error "need a signing kid"
    else if not json?.body?.per_user_key?.encryption_kid?
      new Error "need an encryption kid"
    else null

  _v_check : ({json}, cb) ->
    esc = make_esc cb, "_v_check"
    err = @_find_fields { json }
    if not err?
      await KeyManager.import_public { hex : json.body.per_user_key.signing_kid }, esc defer()
      await EncKeyManager.import_public { hex : json.body.per_user_key.encryption_kid }, esc defer()
      await super { json }, esc defer()
    cb err

  constructor : (obj) ->
    @kms = obj.kms
    @generation = obj.generation
    super obj

#==========================================================================
