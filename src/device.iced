
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Device = class Device extends Base

  constructor : (obj) ->
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.device

  _required_sections : () -> super().concat(["device"])

  _v_customize_json : (ret) ->
    ret.body.device = @device

  _type_v2 : () -> constants.sig_types_v2.device

#==========================================================================
