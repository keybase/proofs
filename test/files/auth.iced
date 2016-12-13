
{KeyManager} = require('kbpgp').kb
{prng} = require 'crypto'
{errors,alloc,Auth} = require '../../'

new_uid = () -> prng(16).toString('hex')
new_username = () -> "u_" + prng(5).toString('hex')
new_user = () -> {uid : new_uid(), username : new_username() }
new_host = () -> prng(4).toString('hex') + ".foo.com"
new_session = () -> "sess-" + prng(16).toString('hex')
new_nonce = () -> "nonce-" + prng(16).toString('hex')
new_email = () -> "foo" + prng(6).toString('hex') + "@foo.com"

test_auth = (T, {gen_hook, verify_hook, err_hook}, cb) ->
  await KeyManager.generate {}, T.esc(defer(km), cb)
  user = new_user()
  host = new_host()
  sig_eng = km.make_sig_eng()
  nonce = new_nonce()
  session = new_session()
  garg = { user : local : user, host, sig_eng, nonce, session }
  gen_hook garg if gen_hook?
  auth = new Auth garg
  await auth.generate T.esc(defer(sig), cb)
  varg = { armored : sig.armored, skip_ids : true, make_ids : true }
  carg = { sig_eng, host, user : local : user }
  verify_hook varg, carg if verify_hook?
  verifier = alloc 'auth', carg
  await verifier.verify varg, defer err
  if err_hook?
    err_hook err
  else
    T.no_error err, "no error expected"
  cb()

exports.test_auth_success = (T,cb) ->
  test_auth T, {}, cb
exports.test_auth_success_uid_only = (T,cb) ->
  test_auth T, { gen_hook : (garg) -> delete garg.user.local.username }, cb
exports.test_auth_success_username_only = (T,cb) ->
  test_auth T, { gen_hook : (garg) -> delete garg.user.local.uid }, cb

exports.test_auth_fail_no_user = (T,cb) ->
  test_auth T, {
    gen_hook : (garg) ->
      delete garg.user.local.uid
      delete garg.user.local.username
    err_hook : (err) ->
      T.assert err?, "errored out on no user"
  }, cb

exports.test_auth_success_email_only = (T,cb) ->
  email = new_email()
  test_auth T, {
    gen_hook : (garg) ->
      delete garg.user.local.uid
      delete garg.user.local.username
      garg.user.local.email = email
    verify_hook : (varg, carg) ->
      carg.user.local.emails = [ email ]
  }, cb

exports.test_auth_success_email_only_upper_case = (T,cb) ->
  email = new_email()
  test_auth T, {
    gen_hook : (garg) ->
      delete garg.user.local.uid
      delete garg.user.local.username
      garg.user.local.email = email.toUpperCase()
    verify_hook : (varg, carg) ->
      carg.user.local.emails = [ email ]
  }, cb

exports.test_auth_failure_wrong_email = (T,cb) ->
  email = new_email()
  test_auth T, {
    gen_hook : (garg) ->
      garg.user.local.email = email
    verify_hook : (varg, carg) ->
      carg.user.local.emails = [ "x" + email ]
    err_hook : (err) ->
      T.assert err?, "errored out on bad email"
  }, cb

exports.test_auth_failure_wrong_uid = (T,cb) ->
  test_auth T, {
    verify_hook : (varg, carg) ->
      carg.user.local.uid = new_uid()
    err_hook : (err) ->
      T.assert err?, "errored out on bad uid"
  }, cb

exports.test_auth_failure_wrong_username = (T,cb) ->
  test_auth T, {
    verify_hook : (varg, carg) ->
      carg.user.local.username = new_username()
    err_hook : (err) ->
      T.assert err?, "errored out on bad uid"
  }, cb

exports.test_auth_failure_wrong_host = (T,cb) ->
  test_auth T, {
    verify_hook : (varg, carg) ->
      carg.host = new_host()
    err_hook : (err) ->
      T.assert err?, "errored out on bad host"
  }, cb

exports.test_auth_failure_no_host = (T,cb) ->
  test_auth T, {
    gen_hook : (garg, carg) ->
      delete garg.host
    err_hook : (err) ->
      T.assert err?, "errored out on no host"
  }, cb

exports.test_bad_ctime = (T,cb) ->
  now = 100000000
  ctime = now + 800
  ccs = 400
  test_auth T, {
    gen_hook : (garg, carg) ->
      garg.ctime = ctime
      garg.now   = now
    verify_hook : (varg, carg) ->
      varg.ctime = ctime
      varg.now   = now
      varg.critical_clock_skew_secs = ccs
    err_hook : (err) ->
      T.assert err?, "errored out bad ctime"
      T.assert (err instanceof errors.ClockSkewError), "the right kind of error"
  }, cb
