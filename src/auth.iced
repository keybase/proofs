
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Auth = class Auth extends Base

  constructor : (obj) ->
    @nonce = obj.nonce
    @session = obj.session
    super obj

  _type : () -> constants.sig_types.auth

  # TODO once legacy clients not using "auth" sections are gone, we should remove
  # "nonce" and "session" and make "auth" required
  _optional_sections : () -> super().concat(["nonce", "session", "auth"])

  _json : () ->
    ret = super { expire_in : 24*60*60 }
    ret.body.auth = {}
    ret.body.auth.nonce = if @nonce then @nonce.toString('hex') else null
    ret.body.auth.session = @session if @session?
    ret

#==========================================================================
