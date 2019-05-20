{sig3,alloc_v3,team_hidden,errors} = require '../../'
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

exports.test_generate_team_hidden_rotate = (T,cb) ->
  esc = make_esc cb
  await gen { T }, esc defer ret
  cb null, ret

gen = (T,cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  rotate_key = { generation : 10 }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.rotate_key = rotate_key
  arg.team = { id : prng(16) }
  await EncKeyManager.generate {}, esc defer rotate_key.enc_km
  await KeyManager.generate {}, esc defer rotate_key.sig_km
  obj = new team_hidden.RotateKey arg
  await obj.generate {}, esc defer ret
  cb null, {ret, km, arg }

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
  rotate_key = { generation : 10 }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.rotate_key = rotate_key
  arg.team = { id : prng(16) }
  await EncKeyManager.generate {}, esc defer rotate_key.enc_km
  await KeyManager.generate {}, esc defer rotate_key.sig_km
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
    rotate_key = { generation : 10 }
    arg = new_sig_arg_v3 { mk_prev : true, km }
    arg.rotate_key = rotate_key
    arg.team = { id : prng(16) }
    await EncKeyManager.generate {}, esc defer rotate_key.enc_km
    await KeyManager.generate {}, esc defer rotate_key.sig_km
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

  await run ((v) -> v.push "foo"), "At outer: need an array with 7 fields", defer()
  await run ((v) -> v.pop()), "At outer: need an array with 7 fields", defer()
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
  rotate_key = { generation : 10 }
  await KeyManager.generate {}, esc defer km
  await EncKeyManager.generate {}, esc defer rotate_key.enc_km
  await KeyManager.generate {}, esc defer rotate_key.sig_km

  run = (f, msg, cb) ->
    arg = new_sig_arg_v3 { mk_prev : true, km }
    arg.rotate_key = rotate_key
    arg.team = { id : prng(16) }
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
  await run ((o) -> o.b.x = 10), "At inner.b.x: key is not supported", defer()
  await run ((o) -> o.b.s = Buffer.alloc(32)), "At inner.b.s: value needs to be buffer of length 35" , defer()
  await run ((o) -> o.b.e = Buffer.alloc(32)), "At inner.b.e: value needs to be buffer of length 35" , defer()
  await run ((o) -> o.b.g = Buffer.alloc(3)), "At inner.b.g: value must be a seqno (sequence number)" , defer()
  await run ((o) -> o.b.a = 4), "At inner.b.a: must be set to value 2" , defer()

  cb null

exports.test_bad_reverse_sig = (T,cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  rotate_key = { generation : 10 }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.rotate_key = rotate_key
  arg.team = { id : prng(16) }
  await EncKeyManager.generate {}, esc defer rotate_key.enc_km
  await KeyManager.generate {}, esc defer rotate_key.sig_km
  obj = new team_hidden.RotateKey arg

  # Hack - instead of assigning the right reverse sig, assign a twiddled
  # signature (with one bit off).
  obj._v_assign_reverse_sig = ({sig, inner}) ->
    if sig?
      twiddle sig
      inner.b.r = sig
  await obj.generate {}, esc defer ret
  await alloc_v3 { km, armored : ret.armored, check_params : _to_check_params(arg) }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "Signature failed to verify", "right error"
  T.assert (err.stack.indexOf("verify_reverse_sig") > 0), "we find a reverse sig in the stack"
  cb null
