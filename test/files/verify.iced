{make_esc} = require 'iced-error'
{alloc,Sibkey,Auth} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{new_sig_arg} = require './util'

test_klass = ({ T, klass, arg, verify_arg, v2, errfunc }, cb) ->
  esc = make_esc cb, 'test_klass'
  obj = new klass arg
  if v2
    await obj.generate_v2 esc defer out
  else
    await obj.generate esc defer out

  typ = out.inner.obj.body.type
  obj2 = alloc typ, verify_arg
  arg = { armored : out.armored, skip_ids : true, make_ids : true }
  if v2
    arg.inner = out.inner.str
  await obj2.verify_all_versions arg, defer err
  if errfunc
    cb if errfunc(err) then null else new Error("Unexpected verify outcome: #{err?.toString()}")
  else
    cb err

test_klass_both_v = (arg, cb) ->
  esc = make_esc cb, 'test_klass_both_v'
  await test_klass Object.assign({}, arg, { v2 : false }), esc defer()
  await test_klass Object.assign({}, arg, { v2 : true }), esc defer()
  cb null

state = {}

exports.init = (T, cb) ->
  esc = make_esc cb, 'init'
  await KeyManager.generate {}, esc defer state.elder
  await KeyManager.generate {}, esc defer state.sib
  state.arg = new_sig_arg { km : state.elder }
  state.arg.sibkm = state.sib
  cb null

exports.test_happy_path = (T, cb) ->
  esc = make_esc cb, 'test_happy_path'
  arg = verify_arg = state.arg
  await test_klass_both_v { T, klass : Sibkey, arg, verify_arg }, esc defer()
  cb null

exports.test_no_eldest_kid_in_sig = (T, cb) ->
  esc = make_esc cb, 'test_no_eldest_kid_in_sig'
  arg = Object.assign {}, state.arg
  delete arg.eldest_kid
  verify_arg = state.arg
  errfunc = (err) -> err?.toString().indexOf("no eldest_kid given") isnt -1
  await test_klass_both_v { T, klass : Sibkey, arg, verify_arg, errfunc }, esc defer()
  cb null

exports.test_wrong_eldest_kid = (T, cb) ->
  esc = make_esc cb, 'test_no_eldest_kid_during_verify'
  arg = state.arg
  verify_arg = Object.assign {}, state.arg
  verify_arg.eldest_kid = Buffer.from(verify_arg.eldest_kid, 'hex').reverse().toString('hex')
  errfunc = (err) -> err?.toString().indexOf("Wrong eldest_kid") isnt -1
  await test_klass_both_v { T, klass : Sibkey, arg, verify_arg, errfunc }, esc defer()
  cb null

exports.test_no_eldest_kid_during_verify = (T, cb) ->
  esc = make_esc cb, 'test_no_eldest_kid_during_verify'
  arg = state.arg
  verify_arg = Object.assign {}, state.arg
  delete verify_arg.eldest_kid
  errfunc = (err) -> err?.toString().indexOf("Local user does not have eldest_kid") isnt -1
  await test_klass_both_v { T, klass : Sibkey, arg, verify_arg, errfunc }, esc defer()
  cb null

exports.test_sigs_without_eldest = (T, cb) ->
  esc = make_esc cb, 'test_sigs_without_eldest'

  arg = new_sig_arg { km : state.elder }
  verify_arg = Object.assign {}, arg
  # Do not pass eldest_kid during creation, but assume counter-party
  # knows and passes eldest_kid during verification. This should not
  # be an error.
  delete arg.eldest_kid
  await test_klass { T, klass : Auth, arg, verify_arg, v2 : false }, esc defer()

  # Test that it still succeeds where both signer and verifiers don't
  # pass eldest_kid.
  delete verify_arg.eldest_kid
  await test_klass { T, klass : Auth, arg, verify_arg, v2 : false }, esc defer()

  cb null
