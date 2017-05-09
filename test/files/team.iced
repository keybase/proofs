{alloc,team} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg} = require './util'
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util

test_klass = ({T,arg, klass, keys}, cb) ->
  esc = make_esc cb, "test_klass"
  delete arg.kms
  delete arg.team.per_team_key
  if keys
    arg.kms = {}
    await EncKeyManager.generate {}, esc defer arg.kms.encryption
    await KeyManager.generate {}, esc defer arg.kms.signing
    arg.kms.generation = 10
  obj = new klass arg
  await obj.generate_v2 esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify_v2 varg, esc defer()
  T.waypoint "checked #{typ} #{if keys then 'with' else 'without'} keys"
  cb null

exports.test_all_classes = (T,cb) ->
  esc = make_esc cb, "test_all_classes"
  klasses = [team.Index, team.Root, team.ChangeMembership, team.RotateKey, team.NewSubteam, team.Leave, team.SubteamHead, team.RenameSubteam ]
  await KeyManager.generate {}, esc defer km
  arg = new_sig_arg { km }
  arg.team = { members : { admin : ["a"] } }
  for klass in klasses
    await test_klass { T, arg, klass, keys : true }, esc defer()
    await test_klass { T, arg, klass, keys : false }, esc defer()
  cb()

exports.test_bad_key_section = (T,cb) ->
  esc = make_esc cb, "test_bad_key_section"
  await KeyManager.generate {}, esc defer km
  arg = new_sig_arg { km }
  arg.team = { members : { admin : ["a"] } }
  arg.kms = {}
  await EncKeyManager.generate {}, esc defer arg.kms.encryption
  await KeyManager.generate {}, esc defer arg.kms.signing
  obj = new team.RotateKey arg
  await obj.generate_v2 esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify_v2 varg, defer err
  T.assert err?, "we got an error back"
  T.equal err.message, "Need per_team_key.generation to be an integer > 0 (got undefined)", "right message"
  cb null

round_trip_with_corrupted_reverse_sig = ({T, corrupt}, cb) ->
  esc = make_esc cb, "test_bad_key_section"
  await KeyManager.generate {}, esc defer km
  arg = new_sig_arg { km }
  arg.team = { members : { admin : ["a"] } }
  arg.kms = {}
  await EncKeyManager.generate {}, esc defer arg.kms.encryption
  await KeyManager.generate {}, esc defer arg.kms.signing
  arg.kms.generation = 10
  obj = new team.RotateKey arg

  obj._v_generate = (opts, cb) ->
    esc = make_esc cb, "_v_generate"
    x = { reverse_sig: null }
    @set_new_key_section x
    eng = @get_new_km().make_sig_eng()
    await @generate_json { version : opts.version }, esc defer msg
    msg2 = JSON.parse msg
    msg2.foo = "bar" if corrupt
    msg = json_stringify_sorted(msg2)
    await eng.box msg, esc defer { armored, type }
    x.reverse_sig = armored
    cb null

  await obj.generate_v2 esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify_v2 varg, defer err
  if corrupt
    T.assert err?, "got an error back"
    T.assert (err.message.indexOf('Reverse sig json mismatch') >= 0), "found right error message"
  cb null

exports.test_corruption_mechanism = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, corrupt : false }, cb

exports.test_reverse_sig_failure = (T,cb) ->
  round_trip_with_corrupted_reverse_sig { T, corrupt : true }, cb
