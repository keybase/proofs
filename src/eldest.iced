
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Eldest = class Eldest extends Base

  constructor : (obj) ->
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.eldest

  _optional_sections : () -> super().concat(["device"])

  _json : () ->
    ret = super {}
    ret.body.device = @device if @device?
    return ret

#==========================================================================
