
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Eldest = class Eldest extends Base

  _v_include_pgp_details : () -> true
  _v_pgp_km : () -> @km()

  constructor : (obj) ->
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.eldest
  _type_v2 : () -> constants.sig_types_v2.eldest

  _optional_sections : () -> super().concat(["device"])

  _v_customize_json : (ret) ->
    ret.body.device = @device if @device?

  # Eldest proofs do not require "eldest_kid" field right now.
  # TODO: In the future, we want to enforce Eldest proofs to contain
  # "eldest_kid" that's equal to "kid" being posted.
  _v_require_eldest_kid : () -> false

#==========================================================================
