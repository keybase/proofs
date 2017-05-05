
{prng} = require 'crypto'

exports.new_uid = new_uid = () -> prng(16).toString('hex')
exports.new_username = new_username = () -> "u_" + prng(5).toString('hex')

exports.skip = 1

exports.new_arg = new_arg = ({km}) ->
  arg =
    user :
      local :
        uid : new_uid()
        username : new_username()
    host : "keybase.io"
    sig_eng : km.make_sig_eng()
    seqno : 0
    prev : null
