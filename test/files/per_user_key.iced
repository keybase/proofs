{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{alloc,PerUserKey} = require '../../'
{prng} = require 'crypto'
{new_arg} = require './util'

exports.test_per_user_key = (T,cb) ->
  esc = make_esc cb, "test_per_user_key"
  await EncKeyManager.generate {}, esc defer ekm
  await KeyManager.generate {}, esc defer skm
  await KeyManager.generate {}, esc defer pkm
  arg = new_arg { km : pkm }
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
