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
  arg.team_id = prng(16)
  await EncKeyManager.generate {}, esc defer rotate_key.enc_km
  await KeyManager.generate {}, esc defer rotate_key.sig_km
  obj = new team_hidden.RotateKey arg
  await obj.generate {}, esc defer ret
  cb null, {ret, km, arg }

exports.test_generate_verify_team_hidden_rotate = (T,cb) ->
  esc = make_esc cb
  await gen { T }, esc defer {ret, km, arg }
  await alloc_v3 { km, armored : ret.armored, check_params : arg }, esc defer { objs }
  await KeyManager.generate {}, esc defer km2
  await alloc_v3 { km : km2, armored : ret.armored, check_params : arg }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "Signature failed to verify", "right error message"

  arg.user.local.uid = twiddle_hex arg.user.local.uid
  await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "bad UID", "got the wrong UID"
  arg.user.local.uid = twiddle_hex arg.user.local.uid

  arg.user.local.eldest_seqno++
  await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "bad eldest_seqno", "got the wrong eldest"
  arg.user.local.eldest_seqno--

  twiddle arg.prev
  await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
  T.assert err?, "got an error"
  T.assert (err instanceof errors.BadPrevError), "right error type"
  twiddle arg.prev

  await alloc_v3 { km, armored : ret.armored, check_params : arg, now : unix_time()+1000000 }, defer err
  T.assert err?, "got an error"
  T.assert (err instanceof errors.ClockSkewError), "right error type"

  inner_armored = ret.armored.inner
  inner = unpack(Buffer.from(ret.armored.inner, "base64"))
  inner.c++
  ret.armored.inner = pack(inner).toString('base64')
  await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
  T.assert err?, "got an error ack"
  T.equal err.message, "outer's body hash doesn't match inner link", "right message"
  ret.armored.inner = inner_armored

  cb null

exports.test_bad_outer = (T,cb) ->
  esc = make_esc cb
  run = (f, msg, cb) ->
    await KeyManager.generate {}, esc defer km
    rotate_key = { generation : 10 }
    arg = new_sig_arg_v3 { mk_prev : true, km }
    arg.rotate_key = rotate_key
    arg.team_id = prng(16)
    await EncKeyManager.generate {}, esc defer rotate_key.enc_km
    await KeyManager.generate {}, esc defer rotate_key.sig_km
    obj = new team_hidden.RotateKey arg
    obj._generate_outer = ({inner}) ->
      return f (new sig3.OuterLink {
        version: obj._version()
        seqno : obj.seqno
        prev : parse.unhex(obj.prev)
        inner_hash : obj._hash(inner)
        link_type : obj._v_link_type_v3()
        chain_type : obj._v_chain_type_v3()
        ignore_if_unsupported : obj.ignore_if_unsupported
      }).encode()
    await obj.generate {}, esc defer ret
    await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
    T.assert err?, "error"
    T.equal err.message, msg, "right message"
    cb null

  f = (v) -> v.push "foo"; return v
  await run f, "outer links must be len 7", defer()
  f = (v) -> v[0]++; return v
  await run f, "outer link slot 0 must be version 3", defer()
  f = (v) -> v[1] = ["hi"]; return v
  await run f, "outer link slot 1 must be a seqno", defer()
  f = (v) -> v[2] = Buffer.alloc(33); return v
  await run f, "outer link slot 2 must be a prev", defer()
  f = (v) -> v[3] = Buffer.alloc(33); return v
  await run f, "outer link slot 3 must be an innerlink hash", defer()
  f = (v) -> v[4] = 1000; return v
  await run f, "outer link slot 4 must be a link type", defer()
  f = (v) -> v[5] = 1000; return v
  await run f, "outer link slot 5 must be a chain type", defer()
  f = (v) -> v[6] = 1000; return v
  await run f, "outer link slot 6 must be a boolean", defer()

  cb null

exports.test_bad_inner = (T,cb) ->
  esc = make_esc cb
  run = (f, msg, cb) ->
    await KeyManager.generate {}, esc defer km
    rotate_key = { generation : 10 }
    arg = new_sig_arg_v3 { mk_prev : true, km }
    arg.rotate_key = rotate_key
    arg.team_id = prng(16)
    await EncKeyManager.generate {}, esc defer rotate_key.enc_km
    await KeyManager.generate {}, esc defer rotate_key.sig_km
    obj = new team_hidden.RotateKey arg
    obj._encode_inner = (opts) ->
      ret = obj._encode_inner_impl opts
      f ret
      ret
    await obj.generate {}, esc defer ret
    await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
    T.assert err?, "error"
    T.equal err.message, msg, "right message"
    cb null

  await run ((o) -> o.c = "blah"), "need a time for c", defer()
  await run ((o) -> o.e = Buffer.alloc(13)), "need 16-byte entropy", defer()
  await run ((o) -> o.m = [1]), "need a merkle root", defer()
  await run ((o) -> o.m.c = [1]), "m.c must be a time", defer()
  await run ((o) -> o.m.h = Buffer.alloc(40)), "m.h must be a 32-byte hash", defer()
  await run ((o) -> o.m.s = -1), "m.s must be a seqno", defer()
  await run ((o) -> delete o.s), "need a signer for s", defer()
  await run ((o) -> o.s.e = "foo"), "need a seqno for s.e", defer()
  await run ((o) -> o.s.e++), "bad eldest_seqno", defer()
  await run ((o) -> o.s.k = Buffer.alloc(30)), "need a kid for s.k", defer()
  await run ((o) -> o.s.u = [1]), "need a uid for s.u", defer()
  await run ((o) -> o.s.u = Buffer.alloc(16)), "bad UID", defer()
  await run ((o) -> o.p.h = Buffer.alloc(30)), "need a hash for p.h", defer()
  await run ((o) -> o.p.s = {}), "need a seqno for p.s", defer()

  cb null

exports.test_bad_reverse_sig = (T,cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  rotate_key = { generation : 10 }
  arg = new_sig_arg_v3 { mk_prev : true, km }
  arg.rotate_key = rotate_key
  arg.team_id = prng(16)
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
  await alloc_v3 { km, armored : ret.armored, check_params : arg }, defer err
  T.assert err?, "got an error"
  T.equal err.message, "Signature failed to verify", "right error"
  T.assert (err.stack.indexOf("verify_reverse_sig") > 0), "we find a reverse sig in the stack"
  cb null
