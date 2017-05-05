{alloc,team} = require '../../'
{KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_arg} = require './util'

exports.test_all_classes = (T,cb) ->
  esc = make_esc cb, "test_all_classes"
  klasses = [team.Index, team.Root, team.ChangeMembership, team.RotateKey, team.NewSubteam, team.Leave, team.SubteamHead, team.RenameSubteam ]
  await KeyManager.generate {}, esc defer km
  arg = new_arg { km }
  arg.team = "test"

  for klass in klasses
    obj = new klass arg
    await obj.generate_v2 esc defer out
    typ = out.inner.obj.body.type
    obj2 = alloc typ, arg
    varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
    await obj2.verify_v2 varg, esc defer()
    T.waypoint "checked #{typ}"

  cb()
