
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.DoNotReset = class DoNotReset extends Base

  constructor : (obj) ->
    super obj

  _type : () -> constants.sig_types.do_not_reset
  _type_v2 : () -> constants.sig_types_v2.do_not_reset
