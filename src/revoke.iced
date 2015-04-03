
{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.Revoke = class Revoke extends Base

  _type : () -> constants.sig_types.revoke

  _v_check : ({json}, cb) ->
    await super { json }, defer err
    unless err?
      err = if not(json.body?.revoke?.sig_id?) and
               not(json.body?.revoke?.sig_ids?) and
               not(json.body?.revoke?.kid?) and
               not(json.body?.revoke?.kids?)
        new Error "Need one of sig_id/sig_ids/kid/kids in signature revoke block"
    cb err

#==========================================================================
