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
    e = (s) -> [(new Error s), null]
    return e("outer links must be arrays") unless typeof(obj) is 'object' and Array.isArray(obj)
    return e("outer links must be len 7") unless obj.length is 7
    return e("outer link slot 0 must be version 3") unless obj[0] is constants.versions.sig_v3
    return e("outer link slot 1 must be a seqno") unless parse.is_seqno obj[1]
    return e("outer link slot 2 must be a prev") unless parse.is_prev obj[2]
    return e("outer link slot 3 must be an innerlink hash") unless parse.is_inner_link_hash obj[3]
    return e("outer link slot 4 must be a link type") unless parse.is_link_type obj[4]
    return e("outer link slot 5 must be a chain type") unless parse.is_chain_type obj[5]
    return e("outer link slot 6 must be a boolean") unless parse.is_bool obj[6]
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

  _generate_inner : (opts, cb) ->
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

  decode_inner : ({json, outer_obj}, cb) ->
    esc = make_esc cb
    e = (m) -> new Error m
    p = () ->
      return e("need a time for c") unless parse.is_time(json.c)
      return e("need 16-byte entropy") unless parse.is_hex(json.e, 16)
      return e("need a merkle root") unless json.m? and parse.is_dict(json.m)
      return e("m.c must be a time") unless parse.is_time(json.m.c)
      return e("m.h must be a 32-byte hash") unless parse.is_hex(json.m.h, 32)
      return e("m.s must be a seqno") unless parse.is_seqno(json.m.s)
      return e("need a signer for s") unless json.s? and parse.is_dict(json.s)
      return e("need a seqno for s.e") unless parse.is_seqno(json.s.e)
      return e("need a kid for s.k") unless parse.is_kid(json.s.k)
      return e("need a uid for s.u") unless parse.is_uid(json.s.u)
      if json.p?
        return e("need a hash for p.h") unless parse.is_hex(json.p.h, 32)
        return e("need a seqno for p.s") unless parse.is_seqno(json.p.s)
        return e("need a chain type for p.t") unless parse.is_chain_type(json.p.t)
      return null
    err = p()
    return cb err if err?

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

  # slight level of indirection for testing purposes
  _encode_inner : (opts) -> @_encode_inner_impl opts

  _encode_inner_impl : (opts) ->
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