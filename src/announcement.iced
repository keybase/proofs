
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Announcement = class Announcement extends Base

  constructor : (obj) ->
    @cryptocurrency = obj.announcement
    super obj

  _type : () -> constants.sig_types.announcement

  _json : () -> 
    ret = super {}
    ret.body.announcement = @announcement
    return ret

#==========================================================================
