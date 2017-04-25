
{Base} = require './base'
{constants} = require './constants'
{make_esc} = require 'iced-error'
pgp_utils = require('pgp-utils')
{json_stringify_sorted,unix_time,streq_secure} = pgp_utils.util

#==========================================================================

class TeamBase extends Base

  constructor : (obj) ->
    @team = obj.team
    super obj

  _required_sections : () -> super().concat [ "team" ]
  _v_customize_json : (ret) -> ret.body.team = @team

#--------------

exports.Index = class Index extends TeamBase
  _type : () -> constants.sig_types.team.index
  _type_v2 : () -> constants.sig_types_v2.team.index

#--------------

exports.Root = class Root extends TeamBase
  _type : () -> constants.sig_types.team.root
  _type_v2 : () -> constants.sig_types_v2.team.root

#--------------

exports.ChangeMembership = class ChangeMembership extends TeamBase
  _type : () -> constants.sig_types.team.change_membership
  _type_v2 : () -> constants.sig_types_v2.team.change_membership

#--------------

exports.RotateKey = class RotateKey extends TeamBase
  _type : () -> constants.sig_types.team.rotate_key
  _type_v2 : () -> constants.sig_types_v2.team.rotate_key

#--------------

exports.Leave = class Leave extends TeamBase
  _type : () -> constants.sig_types.team.leave
  _type_v2 : () -> constants.sig_types_v2.team.leave

#--------------

exports.NewSubteam = class NewSubteam extends TeamBase
  _type : () -> constants.sig_types.team.new_subteam
  _type_v2 : () -> constants.sig_types_v2.team.new_subteam

#--------------

exports.SubteamHead = class SubteamHead extends TeamBase
  _type : () -> constants.sig_types.team.subteam_head
  _type_v2 : () -> constants.sig_types_v2.team.subteam_head

#--------------

