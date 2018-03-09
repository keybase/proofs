{alloc,Wallet} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg} = require './util'
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util

exports.test_wallet_key_happy_path = (T,cb) ->
  esc = make_esc cb, "test_sibkey_happy_path"
  await KeyManager.generate {}, esc defer device
  await KeyManager.generate {}, esc defer stellar
  arg = new_sig_arg { km : device }
  arg.wallet =
    km : stellar
    network : "stellar"
    name : "default"
  obj = new Wallet arg
  await obj.generate esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify varg, esc defer()
  cb null

round_trip_with_corrupted_reverse_sig = ({T, corrupt}, cb) ->
  esc = make_esc cb, "round_trip_with_corrupted_reverse_sig"
  await KeyManager.generate {}, esc defer device
  await KeyManager.generate {}, esc defer stellar
  arg = new_sig_arg { km : device }
  arg.wallet =
    km : stellar
    network : "stellar"
    name : "foo"
  obj = new Wallet arg

  obj._v_generate = (opts, cb) ->
    esc = make_esc cb, "_v_generate"
    x = { reverse_sig: null }
    @set_new_key_section x
    x.kid = @get_new_km().get_ekid().toString('hex')
    eng = @get_new_km().make_sig_eng()
    await @generate_json { version : opts.version }, esc defer msg
    msg2 = JSON.parse msg
    msg2.foo = "bar" if corrupt
    msg = json_stringify_sorted(msg2)
    await eng.box msg, esc defer { armored, type }
    x.reverse_sig = armored
    cb null

  await obj.generate esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify varg, defer err
  if corrupt
    T.assert err?, "got an error back"
    T.assert (err.message.indexOf('Reverse sig json mismatch') >= 0), "found right error message"
  else
    T.no_error err, "in the success case, don't expect an error"
  cb null

exports.test_corruption_mechanism = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, corrupt : false }, cb

exports.test_reverse_sig_failure = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, corrupt : true }, cb
