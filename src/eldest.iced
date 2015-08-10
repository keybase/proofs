
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Eldest = class Eldest extends Base

  _v_include_pgp_hash : () -> true

  constructor : (obj) ->
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.eldest

  _optional_sections : () -> super().concat(["device"])

  _v_customize_json : (ret) ->
    ret.body.device = @device if @device?

#==========================================================================
