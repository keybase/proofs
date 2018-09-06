
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Auth = class Auth extends Base

  constructor : (obj) ->
    @nonce = obj.nonce
    @session = obj.session
    super obj

  _type : () -> constants.sig_types.auth

  _required_sections : () -> super().concat(["auth"])

  _v_customize_json : (ret) ->
    ret.body.auth = {}
    ret.body.auth.nonce = if @nonce then @nonce.toString('hex') else null
    ret.body.auth.session = @session if @session?

  _json : () -> super { expire_in : 24*60*60 }

  # we can get away with only one of the two following
  _v_require_username : () -> false
  _v_require_uid      : () -> false

  # eldest_kid is not required. This type of proof should never appear
  # in sigchain.
  _v_require_eldest_kid : () -> false

#==========================================================================
