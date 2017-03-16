
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Revoke = class Revoke extends Base

  constructor : (obj) ->
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.revoke
  _type_v2 : () -> constants.sig_types_v2.revoke

  _required_sections : () -> super().concat(["revoke"])
  _optional_sections : () -> super().concat(["device"])

  _v_check : ({json}, cb) ->
    await super { json }, defer err
    err = if err? then err
    else if not (r = json.body?.revoke)?
      new Error "Need a 'revoke' section of the signature block"
    else if not(r.sig_id?) and not(r.sig_ids?) and not(r.kid?) and not(r.kids?)
      new Error "Need one of sig_id/sig_ids/kid/kids in signature revoke block"
    cb err

  _v_customize_json : (ret) ->
    ret.body.device = @device if @device?

#==========================================================================
