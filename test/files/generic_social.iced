{alloc,GenericSocialBinding} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_sig_arg} = require './util'

exports.test_generic_social_proof = (T, cb) ->
  esc = make_esc cb, "test_generic_social_proof"
  await KeyManager.generate {}, esc defer device
  arg = new_sig_arg { km : device }
  arg.user.remote = "al1ce"
  arg.remote_service = "cryptopals.social"
  obj = new GenericSocialBinding arg
  await obj.generate esc defer out

  obj2 = alloc "web_service_binding.generic_social", arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify varg, esc defer err

  T.equal obj2.service_obj(), { name : arg.remote_service, username : arg.user.remote }

  cb null
