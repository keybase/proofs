{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.PGPUpdate = class PGPUpdate extends Base

  _v_include_pgp_details : () -> true
  _v_require_pgp_details : () -> true
  _v_pgp_km : () -> @pgpkm

  _type : () -> constants.sig_types.pgp_update

  constructor : ({@pgpkm}) -> super
