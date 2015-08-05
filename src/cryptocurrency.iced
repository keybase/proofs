
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Cryptocurrency = class Cryptocurrency extends Base

  constructor : (obj) ->
    @cryptocurrency = obj.cryptocurrency
    super obj

  _type : () -> constants.sig_types.cryptocurrency

  _required_sections : () -> super().concat(["cryptocurrency"])
  _optional_sections : () -> super().concat(["revoke"])

  _json : () ->
    ret = super {}
    ret.body.cryptocurrency = @cryptocurrency
    return ret

#==========================================================================
