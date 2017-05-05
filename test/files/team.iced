{alloc,team} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg} = require './util'

test_klass = ({T,arg, klass, keys}, cb) ->
  esc = make_esc cb, "test_klass"
  if keys
    arg.kms = {}
    await EncKeyManager.generate {}, esc defer arg.kms.encryption
    await KeyManager.generate {}, esc defer arg.kms.signing
    arg.kms.generation = 10
  else
    delete arg.kms
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

