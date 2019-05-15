kbpgp = require 'kbpgp'
{pack,unpack} = require 'purepack'
{errors} = require './errors'
crypto = require 'crypto'
{make_esc} = require 'iced-error'
{constants} = require './constants'
{bufferify,sha256} = require './util'
parse = require './parse3'
{KeyManager} = kbpgp.kb
pgp_utils = require('pgp-utils')
{unix_time} = pgp_utils.util
schema = require './schema3'

#-------------------------

_pack = (obj) -> pack obj, {sort_keys : true}

#-------------------------

_encode_dict = (d) ->
  ret = {}
  for k,v of d
    ret[k] = _pack(v).toString('base64')
  ret

#-------------------------

exports.OuterLink = class OuterLink

  constructor : ({@version, @seqno, @prev, @inner_hash, @link_type, @chain_type, @ignore_if_unsupported}) ->

  encode : () ->
    return [ # OuterLink encoding
      @version
      @seqno
      @prev
      @inner_hash
      @link_type
      @chain_type
      @ignore_if_unsupported
    ]

  @decode : (obj) ->

    schm = schema.array([
      schema.value(3).name("version")
      schema.seqno().name("seqno")
      schema.binary(32).name("prev").optional()
      schema.binary(32).name("inner_link")
      schema.link_type().name("link_type")
      schema.chain_type().name("chain_type")
      schema.bool().name("ignore_if_unsupported")
    ]).name("outer")

    return [err, null] if (err = schm.check obj)?

    return [null, (new OuterLink {
      version               : obj[0]
      seqno                 : obj[1]
      prev                  : obj[2]
      inner_hash            : obj[3]
      link_type             : obj[4]
      chain_type            : obj[5]
      ignore_if_unsupported : obj[6] })]

#-------------------------

exports.Base = class Base

  constructor : ({@sig_eng, @seqno, @user, @prev, @client, @merkle_root, @ignore_if_unsupported, @ctime, @entropy, @public_chain_tail, @new_sig_km}) ->

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
  _v_do_reverse_sign : -> false
  _v_assign_reverse_sig : ->
  _v_new_sig_km : -> null
  _v_link_type_v3 : -> throw new Error "unimplemented"
  _v_chain_type_v3 : -> throw new Error "unimplemented"
  _get_reverse_sig : -> throw new Error "unimplemented"

  _assign_outer : ({outer_obj}) ->
    @seqno = outer_obj.seqno
    @prev = outer_obj.prev
    @ignore_if_unsupported = outer_obj.ignore_if_unsupported

  _enforce_schema : ({json}, cb) ->
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
        t : schema.chain_type().name("chain_type") }).optional().name("public_chain_tail")
      i : schema.dict({
        d : schema.string().name("description")
        v : schema.string().name("version")
      }).optional().name("client_info")
    }).name("inner")
    @_v_extend_schema schm
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
      @public_chain_tail = {
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
    if (p = @public_chain_tail)?
      json.p = { # PublicChain
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
    payload = _pack outer
    await sig_eng.box payload, esc(defer(res)), { prefix : @_prefix() }
    cb null, res.sig

  _hash : (inner) -> sha256 _pack inner

  _reverse_sign : ({inner, outer}, cb) ->
    esc = make_esc cb
    if not @_v_do_reverse_sign()
      return cb null, { inner, outer }
    if not (k = @_v_new_sig_km())?
      return cb new Error "need a new_sig_km if doing a reverse signature"
    await @_sign { sig_eng : k.make_sig_eng(), outer }, esc defer sig
    @_v_assign_reverse_sig { sig, inner }
    outer = @_generate_outer { inner }
    cb null, { inner, outer }

  verify_reverse_sig : ({inner, outer_obj}, cb) ->
    esc = make_esc cb
    if not @_v_do_reverse_sign()
      return cb null
    if not (k = @_v_new_sig_km())?
      return cb new Error "need a new_sig_km if checking a reverse signature"
    sig = @_v_get_reverse_sig { inner }
    @_v_assign_reverse_sig { sig : null, inner }
    inner_hash = outer_obj.inner_hash
    outer_obj.inner_hash = @_hash(inner)
    outer = outer_obj.encode()
    outer_obj.inner_hash = inner_hash
    @_v_assign_reverse_sig { sig, inner }
    payload = _pack outer
    await k.verify_raw { prefix : @_prefix(), payload, sig }, esc defer()
    cb null

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

  generate : (opts, cb) ->
    esc = make_esc cb
    await @_generate_inner opts, esc defer inner
    outer = @_generate_outer { inner }
    await @_reverse_sign { inner, outer }, esc defer { inner, outer }
    await @_sign { @sig_eng, outer }, esc defer sig
    raw = { outer, inner, sig }
    armored = _encode_dict raw
    cb null, { raw, armored }

#-------------------------