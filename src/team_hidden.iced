{Base} = require './sig3'
{constants} = require './constants'
parse = require './parse3'
{EncKeyManager, KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
schema = require './schema3'
{pack,unpack} = require 'purepack'

#------------------

exports.TeamBase = class TeamBase extends Base

  constructor : (args) ->
    @team = args.team
    super args

  _v_encode_inner : ({json}) ->
    obj = { i : Buffer.from(@team.id, 'hex') }
    obj.m = true if @team.is_implicit
    obj.p = true if @team.is_public
    if @team.admin?
      obj.a = {
        i : @team.admin.id
        s : @team.admin.seqno
        t : @team.admin.chain_type
      }
    json.t = obj

  _v_extend_schema : (schm) ->
    schm.set_key "t", schema.dict({
      a : schema.dict({
        i : schema.binary(16).name("team_id")
        s : schema.seqno().name("seqno")
        t : schema.chain_type().name("chain_type") }).optional().name("implicit_admin")
      i : schema.binary(16).name("team_id")
      m : schema.bool().optional().name("is_implicit")
      p : schema.bool().optional().name("is_public") })

  _v_decode_inner : ({json}, cb) ->
    @team = {
      id : json.t.i
      is_public : !!json.t.p
      is_implicit : !!json.t.m
    }
    if json.t.a?
      @team.admin = {
        id : json.t.a.i
        seqno : json.t.a.s
        chain_type : json.t.a.t
      }
    cb null

  to_v2_team_obj : () ->
    ret = {
      id : @team.id.toString('hex')
      is_implicit : @team.is_implicit
      is_public : @team.is_public
    }
    if @team.admin?
      ret.admin = {
        id : @team.admin.toString('hex')
        seqno : @team.admin.seqno
        chain_type : @team.admin.chain_type
      }
    return ret

#------------------

exports.RotateKey = class RotateKey extends TeamBase

  constructor : (args) ->
    @per_team_keys = args.per_team_keys
    super args

  _v_encode_inner : ({json}) ->
    super { json }
    keys = for k in @per_team_keys
      {
        a : constants.appkey_derivation_version.xor
        c : k.seed_check
        e : k.enc_km.key.ekid()
        g : k.generation
        r : null
        s : k.sig_km.key.ekid()
        t : k.ptk_type
      }
    json.b = { k : keys }

  _v_extend_schema : (schm) ->
    super schm
    elem = schema.dict({
      a : schema.value(constants.appkey_derivation_version.xor).name("appkey_derivation_version")
      c : schema.dict({
        h : schema.binary(32).name("hash")
        v : schema.value(1).name("version") }).name("seed_check")
      e : schema.enc_kid().name("encryption_kid")
      g : schema.seqno().name("generation")
      r : schema.binary(64).name("reverse_sig")
      s : schema.kid().name("signing_kid")
      t : schema.ptk_type().name("ptk_type")
    }).name("key")

    schm.set_key "b", schema.dict({
      k : schema.array(elem).name("keys")
    }).name("body")

  _decode_key : ({key}, cb) ->
    esc = make_esc cb
    ret = {
      generation : key.g
      appkey_derivation_version : key.a
      reverse_sig : key.r
      ptk_type : key.t
    }
    await EncKeyManager.import_public { raw : key.e }, esc defer ret.enc_km
    await KeyManager.import_public { raw : key.s }, esc defer ret.sig_km
    cb null, ret

  _v_decode_inner : ({json}, cb) ->
    esc = make_esc cb
    await super { json }, esc defer()
    @per_team_keys = []
    seen = {}
    for key in json.b.k
      await @_decode_key { key }, esc defer ptk
      if seen[ptk.ptk_type]
        return cb new Error "Repeated PTK type #{ptk.ptk_type} not allowed"
      seen[ptk.ptk_type] = true
      @per_team_keys.push ptk
    cb null

  _v_reverse_sign : ({inner, outer}, cb) ->
    esc = make_esc cb
    for k,i in @per_team_keys
      await @_sign { sig_eng : k.sig_km.make_sig_eng(), outer }, esc defer sig
      inner.b.k[i].r = sig
      outer = @_generate_outer { inner }
    cb null, { inner, outer }

  _v_verify_reverse_sig : ({inner, outer_obj}, cb) ->
    esc = make_esc cb
    reverse_sigs = []
    reverse_sigs = (k.r for k in inner.b.k)
    inner_hash = outer_obj.inner_hash
    for k, i in inner.b.k by -1
      sig = k.r
      k.r = null
      outer_obj.inner_hash = @_hash inner
      outer = outer_obj.encode()
      payload = pack outer
      await @per_team_keys[i].sig_km.verify_raw { prefix : @_prefix(), payload, sig }, esc defer()
    for s, i in reverse_sigs
      inner.b.k[i].r = s
    cb null

  _v_link_type_v3 : () -> constants.sig_types_v3.team.rotate_key
  _v_chain_type_v3 : -> constants.seq_types.TEAM_HIDDEN

  _v_assert_is_v2_legacy : () ->
    return err if err?
    if @per_team_keys.length isnt 1
      return new Error "need exactly one PTK"
    if @per_team_keys[0].ptk_type isnt constants.ptk_types.reader
      return new Error "need a reader PTK (no current support for bot or admin keys)"
    null

  to_v2_team_obj : () ->
    ret = super()
    k = @per_team_keys[0]
    ret.per_team_key =
      encryption_kid : k.enc_km.key.ekid().toString('hex')
      signing_kid : k.sig_km.key.ekid().toString('hex')
      generation : k.generation
      reverse_sig : k.reverse_sig.toString('base64')
    return ret

#------------------