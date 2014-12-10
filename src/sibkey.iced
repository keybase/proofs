
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Sibkey = class Sibkey extends Base

  constructor : (obj) ->
    @sibkey = obj.sibkey
    super obj

  _type : () -> constants.sig_types.sibkey

  _json : () ->
    ret = super {}
    ret.body.sibkey = @sibkey
    return ret

#==========================================================================
