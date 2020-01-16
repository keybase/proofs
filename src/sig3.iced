kbpgp = require 'kbpgp'
{unpack} = require 'purepack'
{errors} = require './errors'
crypto = require 'crypto'
{make_esc} = require 'iced-error'
{constants} = require './constants'
{pack,bufferify,sha256} = require './util'
parse = require './parse3'
{KeyManager} = kbpgp.kb
pgp_utils = require('pgp-utils')
{unix_time} = pgp_utils.util
schema = require './schema3'

#-------------------------

_encode_dict = (d) ->
  ret = { armored : {}, json : {} }
  for k,v of d
    ret.json[k] = pack(v)
    ret.armored[k] = ret.json[k].toString('base64')
  ret

#-------------------------

exports.OuterLink = class OuterLink

  constructor : ({@version, @seqno, @prev, @inner_hash, @link_type, @chain_type, @ignore_if_unsupported, @encryption_parameters}) ->

  encode : () ->
    return [ # OuterLink encoding
      @version
      @seqno
      @prev
      @inner_hash
      @link_type
      @chain_type
      @ignore_if_unsupported
      @encryption_parameters
    ]

  @decode : (obj) ->

    schm = schema.struct([
      schema.value(3).name("version")
      schema.seqno().name("seqno")
      schema.binary(32).name("prev").optional()
      schema.binary(32).name("inner_link")
      schema.link_type().name("link_type")
      schema.chain_type().name("chain_type")
      schema.bool().name("ignore_if_unsupported")
      schema.dict({
        k : schema.enc_kid().name("kid")
        n : schema.binary(24).name("nonce")
        v : schema.int().name("version")
      }).optional().name("encryption_parameters")
    ]).name("outer")

    return [err, null] if (err = schm.check obj)?

    return [null, (new OuterLink {
      version               : obj[0]
      seqno                 : obj[1]
      prev                  : obj[2]
      inner_hash            : obj[3]
      link_type             : obj[4]
      chain_type            : obj[5]
      ignore_if_unsupported : obj[6]
      encryption_parameters : obj[7] })]

  check : (opts, cb) ->
    err = null
    # For now, only support TeamHidden on Chain17 though more combos will become available
    err = new Error "bad chain/link type combo" unless (@chain_type is constants.seq_types.TEAM_HIDDEN) and (@link_type is constants.sig_types_v3.team.rotate_key)
    cb err

#-------------------------

exports.Base = class Base

  constructor : ({@sig_eng, @seqno, @user, @prev, @client, @merkle_root, @ignore_if_unsupported, @ctime, @entropy, @parent_chain_tail}) ->

  # one layer of redirection for the purposes of tests
  _generate_inner : (opts, cb) -> @_generate_inner_impl opts, cb

  _generate_inner_impl : (opts, cb) ->
    esc = make_esc cb
    json = @_encode_inner opts
    opts.json = json
    @_v_encode_inner opts
    delete opts.json
    cb null, json

  _version : -> constants.versions.sig_v3

  _v_generate_inner : ({obj}) ->
  _v_new_sig_km : -> null
  _v_link_type_v3 : -> throw new Error "unimplemented"
  _v_chain_type_v3 : -> throw new Error "unimplemented"
  _v_reverse_sign : ({inner, outer}, cb) -> cb null, { inner, outer }
  _v_verify_reverse_sig : ({inner, outer_obj}, cb) -> cb null
  _v_assert_is_v2_legacy : () -> null

  _assign_outer : ({outer_obj}) ->
    @seqno = outer_obj.seqno
    @prev = outer_obj.prev
    @ignore_if_unsupported = outer_obj.ignore_if_unsupported

  get_schema : () ->
    schm = schema.dict({
      c : schema.time().name("ctime")
      e : schema.binary(16).name("entropy")
      m : schema.dict({
        c : schema.time().name("ctime")
        h : schema.binary(32).name("hash_meta")
        s : schema.seqno().name("seqno") }).name("merkle_root")
      s : schema.dict({
        e : schema.seqno().name("eldest_seqno")
        k : schema.kid().name("kid")
        u : schema.uid().name("uid") }).name("signer")
      p : schema.dict({
        h : schema.binary(32).name("tail")
        s : schema.seqno().name("seqno")
        t : schema.chain_type().name("chain_type") }).optional().name("parent_chain_tail")
      i : schema.dict({
        d : schema.string().name("description")
        v : schema.string().name("version")
      }).optional().name("client_info")
    }).name("inner")
    @_v_extend_schema schm
    return schm

  _enforce_schema : ({json}, cb) ->
    schm = @get_schema()
    cb schm.check json

  decode_inner : ({json, outer_obj}, cb) ->
    esc = make_esc cb

    await @_enforce_schema { json }, esc defer()

    @_assign_outer { outer_obj }

    @ctime = json.c
    @entropy = json.e
    @merkle_root = {
      ctime : json.m.c
      hash_meta : json.m.h
      seqno : json.m.s
    }
    @user = { local : { uid : json.s.u, eldest_seqno : json.s.e } }
    await KeyManager.import_public { raw : json.s. k}, esc defer km
    @sig_eng = km.make_sig_eng()
    if json.p?
      @parent_chain_tail = {
        hash : json.p.h
        seqno : json.p.s
        chain_type : json.p.t
      }
    if json.i?
      @client = {
        name : json.i.d
        version : json.i.v
      }
    await @_v_decode_inner { json }, esc defer()
    cb null

  _encode_inner : (opts) ->
    entropy = @entropy or crypto.prng(16)
    json = {
      c : @ctime
      e : entropy
      m : { # MerkleRoot
        c : @merkle_root.ctime
        h : parse.unhex(@merkle_root.hash_meta)
        s : @merkle_root.seqno }
      s : { # Signer
        e : @user.local.eldest_seqno
        k : @sig_eng.get_km().key.ekid()
        u : parse.unhex(@user.local.uid) } }
    if (p = @parent_chain_tail)?
      json.p = { # ParentChain
        h : parse.unhex(p.hash)
        s : p.seqno
        t : p.chain_type }
    if @client?
      json.i = { # ClientInfo
        d : @client.name
        v : @client.version }
    return json

  _prefix : -> bufferify(constants.sig_prefixes[@_version()])

  _sign : ({sig_eng, outer}, cb) ->
    esc = make_esc cb
    payload = pack outer
    await sig_eng.box payload, esc(defer(res)), { prefix : @_prefix() }
    cb null, res.sig

  _hash : (inner) -> sha256 pack inner

  check : ({now}, cb) ->
    esc = make_esc cb
    await @_check_clock_skew { now }, esc defer()
    cb null

  _check_clock_skew : ({now}, cb) ->
    critical_clock_skew_secs = constants.critical_clock_skew_secs
    now or= unix_time()
    diff = Math.abs(now - @ctime)
    if Math.abs(diff) > critical_clock_skew_secs
      epoch = if now > @ctime then "past" else "future"
      err = new errors.ClockSkewError "your computer's clock is wrong: signature is dated #{diff} seconds in the #{epoch}"
      err.diff = diff
    cb err

  _generate_outer : ({inner}) ->
    return (new OuterLink {
      version: @_version()
      seqno : @seqno
      prev : parse.unhex(@prev)
      inner_hash : @_hash(inner)
      link_type : @_v_link_type_v3()
      chain_type : @_v_chain_type_v3()
      ignore_if_unsupported : @ignore_if_unsupported
    }).encode()

  get_merkle_root_hex : () ->
    return null unless @merkle_root?
    return {
      hash_meta : @merkle_root.hash_meta.toString('hex')
      ctime : @merkle_root.ctime
      seqno : @merkle_root.seqno
    }

  assert_is_v2_legacy : () -> @_v_assert_is_v2_legacy()

  generate : (opts, cb) ->
    esc = make_esc cb
    await @_generate_inner opts, esc defer inner
    outer = @_generate_outer { inner }
    await @_v_reverse_sign { inner, outer }, esc defer { inner, outer }
    await @_sign { @sig_eng, outer }, esc defer sig
    raw = { outer, inner, sig }
    {json, armored} = _encode_dict raw
    cb null, { raw, armored, json }

#-------------------------
