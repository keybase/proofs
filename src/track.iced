
kbpgp = require 'kbpgp'
{Base} = require './base'
{constants} = require './constants'
{bufeq_secure,unix_time} = kbpgp.util

#==========================================================================

class Track extends Base

  constructor : (obj) ->
    @tracking = obj.tracking

  _type : () -> constants.sig_types.track

  _json : () -> 
    ret = super {}
    ret.tracking = @tracking
    return ret

#==========================================================================
