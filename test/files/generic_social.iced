{alloc,GenericSocialBinding} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg} = require './util'

generic_name_regexp = /^[a-z0-9_-]{2,15}$/

exports.test_generic_social_proof = (T, cb) ->
  esc = make_esc cb, "test_generic_social_proof"
  await KeyManager.generate {}, esc defer device
  arg = new_sig_arg { km : device }
  arg.user.remote = "al1ce"
  arg.remote_service = "cryptopals.social"
  arg.name_regexp = generic_name_regexp
  obj = new GenericSocialBinding arg
  await obj.generate esc defer out

  obj2 = alloc "web_service_binding.generic_social", arg
  err = obj2.check_inputs()
  T.assert not(err?), "expects check_inputs not to return error, returned: #{err?.toString()}"
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify varg, esc defer err

  T.equal obj2.service_obj(), { name : arg.remote_service, username : arg.user.remote }

  cb null

exports.test_generic_social_inputs = (T, cb) ->
  assert_err = (err, str) ->
    err_str = err?.toString()
    T.assert err_str?.indexOf(str) isnt -1, "Expecting error to contain '#{str}', got: #{err_str}"

  esc = make_esc cb, "test_generic_social_proof"
  await KeyManager.generate {}, esc defer device
  arg = new_sig_arg { km : device }
  arg.user.remote = "b0b"
  arg.remote_service = "cryptopals"
  arg.name_regexp = generic_name_regexp
  obj = new GenericSocialBinding arg
  err = obj.check_inputs()
  assert_err err, "invalid remote_service"

  arg.remote_service = "cryptopals.club"
  arg.user.remote = "HelloBobby$$$"
  obj = new GenericSocialBinding arg
  err = obj.check_inputs()
  assert_err err, "Bad remote_username given"

  arg = new_sig_arg { km : device }
  arg.user.remote = "b0b"
  arg.remote_service = "cryptopals.club"
  obj = new GenericSocialBinding arg
  err = obj.check_inputs()
  assert_err err, "No name_regexp given"

  # Invalid regexp
  arg.name_regexp = "[1-.]{1,5}"
  obj = new GenericSocialBinding arg
  err = obj.check_inputs()
  assert_err err, "No name_regexp given"

  cb null


