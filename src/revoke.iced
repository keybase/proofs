
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Revoke = class Revoke extends Base

  constructor : (obj) ->
    @revoke = obj.revoke
    super obj

  _type : () -> constants.sig_types.auth

  _json : () -> 
    ret = super {}
    ret.body.revoke = @revoke
    ret

#==========================================================================
