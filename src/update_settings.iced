
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.UpdateSettings = class UpdateSettings extends Base

  constructor : (obj) ->
    @update_settings = obj.update_settings
    super obj

  _type : () -> constants.sig_types.update_settings

  _required_sections : () -> super().concat(["update_settings"])

  _v_customize_json : (ret) ->
    ret.body.update_settings = @update_settings

  _json : -> super { expire_in : 24*60*60 }

#==========================================================================
