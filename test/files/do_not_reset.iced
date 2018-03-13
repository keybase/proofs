{alloc,DoNotReset} = require '../../'
{KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg} = require './util'

dnr_gen_and_verify = ({T, v2},cb) ->
  esc = make_esc cb, "dnr_gen_and_verify"
  await KeyManager.generate {}, esc defer device
  arg = new_sig_arg { km : device }
  obj = new DoNotReset arg
  if v2
    await obj.generate_v2 esc defer out
  else
    await obj.generate esc defer out
  typ = out.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  if v2
    await obj2.verify_v2 varg, esc defer()
  else
    await obj2.verify varg, esc defer()
  cb null

exports.test_dnr_happy_path = (T,cb) ->
  esc = make_esc cb, "test_dnr_happy_path"
  await dnr_gen_and_verify {T, v2 : false}, esc defer()
  await dnr_gen_and_verify {T, v2 : true}, esc defer()
  cb null
