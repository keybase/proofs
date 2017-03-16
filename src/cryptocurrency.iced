
{Base} = require './base'
{constants} = require './constants'
{address} = require 'bitcoyne'
{make_esc} = require 'iced-error'

#==========================================================================

exports.Cryptocurrency = class Cryptocurrency extends Base

  constructor : (obj) ->
    @cryptocurrency = obj.cryptocurrency
    super obj

  _type : () -> constants.sig_types.cryptocurrency

  _type_v2 : (revoke_flag) ->
    if @revoke? or revoke_flag then constants.sig_types_v2.cryptocurrency_with_revoke
    else constants.sig_types_v2.cryptocurrency

  _required_sections : () -> super().concat(["cryptocurrency"])
  _optional_sections : () -> super().concat(["revoke"])

  _v_customize_json : (ret) ->
    ret.body.cryptocurrency = @cryptocurrency

  _v_check : (args, cb) ->
    {json} = args
    esc = make_esc cb, "Cryptocurrency::_v_check"
    await super args, esc defer()
    if not (section = json.body.cryptocurrency)?
      err = new Error "needed a cryptocurrency section"
    else
      [err,ret] = address.check_btc_or_zcash section.address
      if not err? and (ret.type isnt section.type)
        err = new Error "wrong cryptocurrency type: wanted #{ret.type} to match given address"
    cb err

#==========================================================================
