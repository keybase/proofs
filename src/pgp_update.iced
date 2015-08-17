{Base} = require './base'
{constants} = require './constants'

#==========================================================================

exports.PGPUpdate = class PGPUpdate extends Base

  _v_include_pgp_hash : () -> true
  _v_require_full_pgp_hash : () -> true
  _v_pgp_km_to_hash : () -> @pgpkm

  _type : () -> constants.sig_types.pgp_update

  constructor : ({@pgpkm}) -> super
