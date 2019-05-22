{Base} = require './sig3'
{constants} = require './constants'
parse = require './parse3'
{EncKeyManager, KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
schema = require './schema3'

#------------------

exports.TeamBase = class TeamBase extends Base

  constructor : (args) ->
    @team = args.team
    super args

  _v_encode_inner : ({json}) ->
    obj = { i : Buffer.from(@team.id, 'hex') }
    obj.m = true if @team.is_implicit
    obj.p = true if @team.is_public
    json.t = obj

  _v_extend_schema : (schm) ->
    schm.set_key "t", schema.dict {
      i : schema.binary(16).name("team_id")
      m : schema.bool().optional().name("is_implicit")
      p : schema.bool().optional().name("is_public")
    }

  _v_decode_inner : ({json}, cb) ->
    @team = {
      id : json.t.i
      is_public : !!json.t.p
      is_implicit : !!json.t.m
    }
    cb null

  to_v2_team_obj : () ->
    {
      id : @team.id.toString('hex')
      is_implicit : @team.is_implicit
      is_public : @team.is_public
    }

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
      e : schema.enc_kid().name("encryption_kid")
      g : schema.seqno().name("generation")
      r : schema.binary(64).name("reverse_sig")
      s : schema.kid().name("signing_kid")
    }).name("body")

  _v_decode_inner : ({json}, cb) ->
    esc = make_esc cb
    await super { json }, esc defer()
    @rotate_key = { generation : json.b.g }
    await EncKeyManager.import_public { raw : json.b.e }, esc defer @rotate_key.enc_km
    await KeyManager.import_public { raw : json.b.s }, esc defer @rotate_key.sig_km
    @rotate_key.reverse_sig = json.b.r
    cb null

  _v_link_type_v3 : () -> constants.sig_types_v3.team.rotate_key
  _v_do_reverse_sign : () -> true
  _v_assign_reverse_sig : ({sig, inner}) -> inner.b.r = sig
  _v_get_reverse_sig : ({inner}) -> inner.b.r
  _v_new_sig_km : () -> @rotate_key.sig_km
  _v_chain_type_v3 : -> constants.seq_types.TEAM_HIDDEN

  to_v2_team_obj : () ->
    ret = super()
    ret.per_team_key =
      encryption_kid : @rotate_key.enc_km.key.ekid().toString('hex')
      signing_kid : @rotate_key.sig_km.key.ekid().toString('hex')
      generation : @rotate_key.generation
      reverse_sig : @rotate_key.reverse_sig.toString('base64')
    return ret

#------------------