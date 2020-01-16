{sig3,alloc_v3,team_hidden,errors,constants} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg_v3} = require './util'
{prng} = require 'crypto'
{pack,unpack} = require 'purepack'
parse = require '../../lib/parse3'
pgp_utils = require('pgp-utils')
{unix_time} = pgp_utils.util

twiddle = (b) -> b[0] ^= 1
twiddle_hex = (b) ->
  buf = Buffer.from(b, 'hex')
  twiddle buf
  buf.toString('hex')

_to_check_params = (a) ->
  return {
    user : a.user
    seqno : a.seqno
    prev : a.prev
  }

seed_check = (ptk) -> ptk.seed_check = { h : prng(32), v : 1 }

exports.test_generate_team_hidden_rotate = (T,cb) ->
  esc = make_esc cb
  await gen { T }, esc defer { km, ret, arg }
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, esc defer()
  cb null, ret

exports.test_generate_team_hidden_rotate_with_implicit_admin = (T,cb) ->
  esc = make_esc cb
  admin = {
    id : prng(16)
    seqno : 20
    chain_type : 3
  }
  f = (arg) -> arg.team.admin = admin
  await gen { T, f }, esc defer { km, ret, arg }
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, esc defer ret
  T.equal ret.objs.inner.team.admin, admin, "admin is right"
  cb null

gen = ({T,f},cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  ptk = { generation : 10, ptk_type : constants.ptk_types.reader }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.per_team_keys = [ ptk ]
  arg.team = { id : prng(16) }
  await EncKeyManager.generate {}, esc defer ptk.enc_km
  await KeyManager.generate {}, esc defer ptk.sig_km
  seed_check ptk
  f? arg
  obj = new team_hidden.RotateKey arg
  await obj.generate {}, esc defer ret
  cb null, {ret, km, arg }

exports.test_head = (T,cb) ->
  esc = make_esc cb
  f = (arg) ->
    arg.seqno = 1
    arg.prev = null
  await gen { T, f }, esc defer { km, ret, arg }
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, esc defer()
  cb null

exports.test_many_ptks = (T,cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.team = { id : prng(16) }
  arg.per_team_keys = []
  constants.ptk_types.bot = 999
  constants.ptk_types.admin = 9999
  for i in Object.values(constants.ptk_types)
    ptk = { generation : 10, ptk_type : i }
    await EncKeyManager.generate {}, esc defer ptk.enc_km
    await KeyManager.generate {}, esc defer ptk.sig_km
    seed_check ptk
    arg.per_team_keys.push ptk
  obj = new team_hidden.RotateKey arg
  await obj.generate {}, esc defer ret
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, esc defer { objs }
  T.equal objs.inner.per_team_keys.length, 3, "3 ptks"

  arg.per_team_keys[0].ptk_type = 0
  arg.per_team_keys[1].ptk_type = 0
  await obj.generate {}, esc defer ret
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error back if repeating the type"
  T.equal err.message, "Repeated PTK type 0 not allowed", "right message"

  arg.per_team_keys[1].ptk_type = 100
  await obj.generate {}, esc defer ret
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error back if using a bad PTK type"
  T.equal err.message, "At inner.b.k.1.t: value must be a PTK type"

  cb null

exports.test_generate_verify_team_hidden_rotate = (T,cb) ->
  esc = make_esc cb
  await gen { T }, esc defer {ret, km, arg }
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, esc defer { objs }
  await KeyManager.generate {}, esc defer km2
  await alloc_v3 { km : km2, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "Signature failed to verify", "right error message"

  arg.user.local.uid = twiddle_hex arg.user.local.uid
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "bad UID", "got the wrong UID"
  arg.user.local.uid = twiddle_hex arg.user.local.uid

  arg.user.local.eldest_seqno++
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "bad eldest_seqno", "got the wrong eldest"
  arg.user.local.eldest_seqno--

  twiddle arg.prev
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error"
  T.assert (err instanceof errors.BadPrevError), "right error type"
  twiddle arg.prev

  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg), now : unix_time()+1000000 }, defer err
  T.assert err?, "got an error"
  T.assert (err instanceof errors.ClockSkewError), "right error type"

  inner_armored = ret.armored.inner
  inner = unpack(Buffer.from(ret.armored.inner, "base64"))
  inner.c++
  ret.armored.inner = pack(inner).toString('base64')
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error ack"
  T.equal err.message, "outer's body hash doesn't match inner link", "right message"
  ret.armored.inner = inner_armored

  cb null

exports.test_bad_encoding = (T,cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  ptk = { generation : 10, ptk_type : constants.ptk_types.reader }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.per_team_keys = [ ptk ]
  arg.team = { id : prng(16) }
  await EncKeyManager.generate {}, esc defer ptk.enc_km
  await KeyManager.generate {}, esc defer ptk.sig_km
  seed_check ptk
  obj = new team_hidden.RotateKey arg
  await obj.generate {}, esc defer ret
  s = ret.armored.inner
  n = 30
  ret.armored.inner = s[0...n] + " " + s[n...]
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "error"
  T.equal err.message, "non-canonical base64-encoding in inner", "right message"
  cb null

exports.test_bad_outer = (T,cb) ->
  esc = make_esc cb
  run = (f, msg, cb) ->
    await KeyManager.generate {}, esc defer km
    ptk = { generation : 10, ptk_type : constants.ptk_types.reader }
    arg = new_sig_arg_v3 { mk_prev : true, km }
    arg.per_team_keys = [ ptk ]
    arg.team = { id : prng(16) }
    await EncKeyManager.generate {}, esc defer ptk.enc_km
    await KeyManager.generate {}, esc defer ptk.sig_km
    ptk.seed_check = { h : prng(32), v : 1 }
    obj = new team_hidden.RotateKey arg
    obj._generate_outer = ({inner}) ->
      ret = (new sig3.OuterLink {
        version: obj._version()
        seqno : obj.seqno
        prev : parse.unhex(obj.prev)
        inner_hash : obj._hash(inner)
        link_type : obj._v_link_type_v3()
        chain_type : obj._v_chain_type_v3()
        ignore_if_unsupported : obj.ignore_if_unsupported
      }).encode()
      f ret
      ret
    await obj.generate {}, esc defer ret
    await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
    T.assert err?, "error"
    T.equal err.message, msg, "right message"
    cb null

  await run ((v) -> v.push "foo"), "At outer: need an array with 8 fields", defer()
  await run ((v) -> v.pop()), "At outer: need an array with 8 fields", defer()
  await run ((v) -> v[0]++), "At outer.0: must be set to value 3", defer()
  await run ((v) -> v[1] = ["hi"]), "At outer.1: value must be a seqno (sequence number)", defer()
  await run ((v) -> v[2] = Buffer.alloc(33)), "At outer.2: value needs to be buffer of length 32", defer()
  await run ((v) -> v[3] = Buffer.alloc(33)), "At outer.3: value needs to be buffer of length 32", defer()
  await run ((v) -> v[4] = 1000), "At outer.4: value must be a valid link type", defer()
  await run ((v) -> v[5] = 1000), "At outer.5: value must be a valid chain type", defer()
  await run ((v) -> v[5] = 3), "bad chain/link type combo", defer()

  cb null

exports.test_bad_inner = (T,cb) ->

  esc = make_esc cb
  ptk = { generation : 10, ptk_type : constants.ptk_types.reader }
  await KeyManager.generate {}, esc defer km
  await EncKeyManager.generate {}, esc defer ptk.enc_km
  await KeyManager.generate {}, esc defer ptk.sig_km
  seed_check ptk

  run = (f, msg, cb) ->
    arg = new_sig_arg_v3 { mk_prev : true, km }
    arg.per_team_keys = [ ptk ]
    arg.team = { id : prng(16), admin : { id : prng(16), seqno : 19, chain_type : 3 } }
    obj = new team_hidden.RotateKey arg
    obj._generate_inner = (opts, cb) ->
      await obj._generate_inner_impl opts, defer err, json
      f json
      cb err, json
    await obj.generate {}, esc defer ret
    await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
    T.assert err?, "error"
    T.equal err.message, msg, "right message"
    cb null

  await run ((o) -> o.c = "blah"), "At inner.c: value must be a UTC timestamp", defer()
  await run ((o) -> o.e = Buffer.alloc(13)), "At inner.e: value needs to be buffer of length 16", defer()
  await run ((o) -> o.m = [1]), "At inner.m: need a dictionary", defer()
  await run ((o) -> o.m.c = [1]), "At inner.m.c: value must be a UTC timestamp", defer()
  await run ((o) -> o.m.h = Buffer.alloc(40)), "At inner.m.h: value needs to be buffer of length 32", defer()
  await run ((o) -> o.m.s = -1), "At inner.m.s: value must be a seqno (sequence number)", defer()
  await run ((o) -> delete o.s), "At inner.s: key is missing but is mandatory", defer()
  await run ((o) -> o.s.e = "foo"), "At inner.s.e: value must be a seqno (sequence number)", defer()
  await run ((o) -> o.s.e++), "bad eldest_seqno", defer()
  await run ((o) -> o.s.k = Buffer.alloc(30)), "At inner.s.k: value needs to be buffer of length 35", defer()
  await run ((o) -> o.s.u = [1]), "At inner.s.u: value needs to be buffer of length 16", defer()
  await run ((o) -> o.s.u = Buffer.alloc(16)), "bad UID", defer()
  await run ((o) -> o.p.h = Buffer.alloc(30)), "At inner.p.h: value needs to be buffer of length 32", defer()
  await run ((o) -> o.p.s = {}), "At inner.p.s: value must be a seqno (sequence number)", defer()
  await run ((o) -> o.i.d = 10), "At inner.i.d: value must be a string", defer()
  await run ((o) -> o.i.v = 10), "At inner.i.v: value must be a string", defer()
  await run ((o) -> o.x = 10), "At inner.x: key is not supported", defer()
  await run ((o) -> o.i.x = 10), "At inner.i.x: key is not supported", defer()
  await run ((o) -> o.m.x = 10), "At inner.m.x: key is not supported", defer()
  await run ((o) -> o.t.i = 10), "At inner.t.i: value needs to be buffer of length 16", defer()
  await run ((o) -> o.t = 10), "At inner.t: need a dictionary", defer()
  await run ((o) -> o.b.k[0].x = 10), "At inner.b.k.0.x: key is not supported", defer()
  await run ((o) -> o.b.k[0].s = Buffer.alloc(32)), "At inner.b.k.0.s: value needs to be buffer of length 35" , defer()
  await run ((o) -> o.b.k[0].e = Buffer.alloc(32)), "At inner.b.k.0.e: value needs to be buffer of length 35" , defer()
  await run ((o) -> o.b.k[0].g = Buffer.alloc(3)), "At inner.b.k.0.g: value must be a seqno (sequence number)" , defer()
  await run ((o) -> o.b.k[0].a = 4), "At inner.b.k.0.a: must be set to value 1" , defer()
  await run ((o) -> o.t.a = 10), "At inner.t.a: need a dictionary", defer()
  await run ((o) -> o.t.a.i = 10), "At inner.t.a.i: value needs to be buffer of length 16", defer()
  await run ((o) -> o.t.a.t = 4), "At inner.t.a.t: value must be a valid chain type", defer()
  await run ((o) -> o.t.a.s = "f"), "At inner.t.a.s: value must be a seqno (sequence number)", defer()

  cb null

exports.test_bad_reverse_sig = (T,cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  ptk = { generation : 10, ptk_type : constants.ptk_types.reader }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.per_team_keys = [ ptk ]
  arg.team = { id : prng(16) }
  await EncKeyManager.generate {}, esc defer ptk.enc_km
  await KeyManager.generate {}, esc defer ptk.sig_km
  seed_check ptk
  obj = new team_hidden.RotateKey arg

  # Hack - instead of assigning the right reverse sig, assign a twiddled
  # signature (with one bit off).
  obj._v_reverse_sign = ({inner, outer}, cb) ->
    esc = make_esc cb
    for k,i in obj.per_team_keys
      await obj._sign { sig_eng : k.sig_km.make_sig_eng(), outer }, esc defer sig
      twiddle sig
      inner.b.k[i].r = sig
      outer = obj._generate_outer { inner }
    cb null, { inner, outer }

  await obj.generate {}, esc defer ret
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "Signature failed to verify", "right error"
  T.assert (err.stack.indexOf("_v_verify_reverse_sig") > 0), "we find a reverse sig in the stack"
  cb null

exports.test_schema_localize = (T, cb) ->
  esc = make_esc cb
  await gen { T }, esc defer { km, ret, arg }
  [err, outer_obj] = sig3.OuterLink.decode ret.raw.outer
  T.no_error err

  obj = new team_hidden.RotateKey {}
  await obj.decode_inner { json: ret.raw.inner, outer_obj }, esc defer()
  localized = obj.get_schema().debug_localize(ret.raw.inner)

  for f in ['ctime', 'entropy', 'merkle_root', 'signer', 'parent_chain_tail', 'client_info', 'team', 'body']
    T.assert localized[f]?, "looking for field #{f}"
  for f in ['ctime', 'hash_meta', 'seqno']
    T.assert localized.merkle_root?[f]?, "looking for field merkle_root.#{f}"
  for f in ['eldest_seqno', 'kid', 'uid']
    T.assert localized.signer?[f]?, "looking for field signer.#{f}"
  for f in ['tail', 'seqno', 'chain_type']
    T.assert localized.parent_chain_tail?[f]?, "looking for field parent_chain_tail.#{f}"
  for f in ['description', 'version']
    T.assert localized.client_info?[f]?, "looking for field client_info.#{f}"
  for f in ['team_id', 'is_implicit', 'is_public']
    T.assert localized.team?[f]?, "looking for field team.#{f}"
  T.assert localized.body?.keys?, "looking for localized.body.keys"
  for k in localized.body?.keys ? []
    for f in ['appkey_derivation_version', 'seed_check', 'encryption_kid', 'generation', 'reverse_sig', 'signing_kid', 'ptk_type']
      T.assert k[f]?, "looking for field body.keys.#{f}"

  cb null
