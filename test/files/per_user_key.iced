{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{alloc,PerUserKey} = require '../../'
{prng} = require 'crypto'
{new_sig_arg} = require './util'
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util

exports.test_per_user_key = (T,cb) ->
  esc = make_esc cb, "test_per_user_key"
  await EncKeyManager.generate {}, esc defer ekm
  await KeyManager.generate {}, esc defer skm
  await KeyManager.generate {}, esc defer pkm
  arg = new_sig_arg { km : pkm }
  arg.kms =
    encryption : ekm
    signing : skm
  arg.generation = 1
  pf = new PerUserKey arg
  await pf.generate_v2 esc defer out
  pf2 = alloc out.inner.obj.body.type, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await pf2.verify_v2 varg, esc defer()
  cb()

round_trip_with_corrupted_reverse_sig = ({T, corrupt, skip_reverse_sig}, cb) ->
  esc = make_esc cb, "round_trip_with_corrupted_reverse_sig"
  await KeyManager.generate {}, esc defer elder
  await KeyManager.generate {}, esc defer skm
  await EncKeyManager.generate {}, esc defer ekm
  arg = new_sig_arg { km : elder }
  arg.kms =
    encryption : ekm
    signing : skm
  arg.generation = 3
  obj = new PerUserKey arg

  obj._v_generate = (opts, cb) ->
    esc = make_esc cb, "_v_generate"
    x = { reverse_sig: null }
    @set_new_key_section x
    x.signing_kid = @get_new_km().get_ekid().toString('hex')
    eng = @get_new_km().make_sig_eng()
    await @generate_json { version : opts.version }, esc defer msg
    msg2 = JSON.parse msg
    msg2.foo = "bar" if corrupt
    msg = json_stringify_sorted(msg2)
    await eng.box msg, esc defer { armored, type }
    x.reverse_sig = armored unless skip_reverse_sig
    cb null

  await obj.generate esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify varg, defer err
  if corrupt
    T.assert err?, "got an error back"
    T.assert (err.message.indexOf('Reverse sig json mismatch') >= 0), "found right error message"
  else if skip_reverse_sig
    T.assert err?, "got an error back"
    T.assert (err.message.indexOf("Need a reverse sig, but didn't find one") >= 0), "found right error message"
  else
    T.no_error err, "in the success case, don't expect an error"
  cb null

exports.test_corruption_mechanism = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, corrupt : false }, cb

exports.test_reverse_sig_failure = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, corrupt : true }, cb

exports.test_reverse_sig_failure = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, skip_reverse_sig : true }, cb
