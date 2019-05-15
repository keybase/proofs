{Base} = require './sig3'
{constants} = require './constants'
parse = require './parse3'
{EncKeyManager, KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
schema = require './schema3'

#------------------

exports.TeamBase = class TeamBase extends Base

  constructor : (args) ->
    @team_id = args.team_id
    super args

  _v_encode_inner : ({json}) ->
    json.t = Buffer.from(@team_id, 'hex')

  _v_extend_schema : (schm) ->
    schm.set_key "t", schema.binary(16).name("team_id")

  _v_decode_inner : ({json}, cb) ->
    @team_id = json.t
    cb null

#------------------

exports.RotateKey = class RotateKey extends TeamBase

  constructor : (args) ->
    @rotate_key = args.rotate_key
    super args

  _v_encode_inner : ({json}) ->
    super { json }
    json.b = { # Body
      a : constants.appkey_derivation_version.hmac
      e : @rotate_key.enc_km.key.ekid()
      g : @rotate_key.generation
      r : null
      s : @rotate_key.sig_km.key.ekid() }

  _v_extend_schema : (schm) ->
    super schm
    schm.set_key "b", schema.dict({
      a : schema.value(constants.appkey_derivation_version.hmac).name("appkey_derivation_version")
      e : schema.enc_kid().name("encryption")
      g : schema.seqno().name("generation")
      r : schema.binary(64).name("reverse_sig")
      s : schema.kid().name("signing")
    }).name("body")

  _v_decode_inner : ({json}, cb) ->
    esc = make_esc cb
    await super { json }, esc defer()
    @rotate_key = { generation : json.b.g }
    await EncKeyManager.import_public { raw : json.b.e }, esc defer @rotate_key.enc_km
    await KeyManager.import_public { raw : json.b.s }, esc defer @rotate_key.sig_km
    cb null

  _v_link_type_v3 : () -> constants.sig_types_v3.team.rotate_key
  _v_do_reverse_sign : () -> true
  _v_assign_reverse_sig : ({sig, inner}) -> inner.b.r = sig
  _v_get_reverse_sig : ({inner}) -> inner.b.r
  _v_new_sig_km : () -> @rotate_key.sig_km
  _v_chain_type_v3 : -> constants.seq_types.TEAM_HIDDEN

#------------------