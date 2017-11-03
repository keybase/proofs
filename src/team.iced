
{Base} = require './base'
{constants} = require './constants'
{make_esc} = require 'iced-error'
pgp_utils = require('pgp-utils')
{json_stringify_sorted,unix_time,streq_secure} = pgp_utils.util
{SubkeyBase} = require './subkey'
{EncKeyManager,KeyManager} = require('kbpgp').kb

#==========================================================================

exports.TeamBase = class TeamBase extends SubkeyBase

  constructor : (obj) ->
    @team = obj.team
    @kms = obj.kms
    super obj

  # Not needed since we override the methods that were calling these
  # helpers.
  sibkid_slot : () -> null
  get_key_field : () -> null

  _required_sections : () -> super().concat [ "team" ]
  _v_customize_json : (ret) ->
    ret.body.team = @team
    if @per_team_key?
      ret.body.team.per_team_key = @per_team_key

  _v_generate : (opts, cb) ->
    err = null
    if @kms?
      await super opts, defer err
    cb err

  get_new_key_section : () -> @per_team_key
  set_new_key_section : (m) ->
    m.generation = @kms.generation
    m.encryption_kid = @kms.encryption.get_ekid().toString('hex')
    m.signing_kid = @kms.signing.get_ekid().toString('hex')
    @per_team_key = m
  get_new_km : () -> @kms?.signing # use the signing KM
  need_reverse_sig : (json) -> json?.body?.team?.per_team_key?

  _get_reverse_sig : (json) -> json?.body?.team?.per_team_key?.reverse_sig
  _get_new_sibkid : (json) -> json?.body?.team?.per_team_key?.signing_kid
  _clear_reverse_sig : (json) -> json.body.team.per_team_key.reverse_sig = null

  _v_include_pgp_details : () -> false

  _find_fields : ({json}) ->
    if (typeof(v = json?.generation) isnt 'number') or (parseInt(v) <= 0)
      new Error "Need per_team_key.generation to be an integer > 0 (got #{v})"
    else if not json?.signing_kid?
      new Error "need a signing kid"
    else if not json?.encryption_kid?
      new Error "need an encryption kid"
    else null

  _v_check : ({json}, cb) ->
    esc = make_esc cb, "_v_check"
    err = null
    if (o = json?.body?.team?.per_team_key)?
      err = @_find_fields { json : o}
      if not err?
        await KeyManager.import_public { hex : o.signing_kid }, esc defer()
        await EncKeyManager.import_public { hex : o.encryption_kid }, esc defer()
    unless err?
      await super { json }, esc defer()
    cb err

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

exports.RenameSubteam = class RenameSubteam extends TeamBase
  _type : () -> constants.sig_types.team.rename_subteam
  _type_v2 : () -> constants.sig_types_v2.team.rename_subteam

#--------------

exports.RenameUpPointer = class RenameUpPointer extends TeamBase
  _type : () -> constants.sig_types.team.rename_up_pointer
  _type_v2 : () -> constants.sig_types_v2.team.rename_up_pointer

#--------------

exports.DeleteSubteam  = class Delete extends TeamBase
  _type : () -> constants.sig_types.team.delete_subteam
  _type_v2 : () -> constants.sig_types_v2.team.delete_subteam

#--------------

exports.DeleteRoot = class DeleteRoot extends TeamBase
  _type : () -> constants.sig_types.team.delete_root
  _type_v2 : () -> constants.sig_types_v2.team.delete_root

#--------------

exports.DeleteUpPointer = class DeleteUpPointer extends TeamBase
  _type : () -> constants.sig_types.team.delete_up_pointer
  _type_v2 : () -> constants.sig_types_v2.team.delete_up_pointer

#--------------

exports.Invite = class Invite extends TeamBase
  _type : () -> constants.sig_types.team.invite
  _type_v2 : () -> constants.sig_types_v2.team.invite

#--------------

exports.LegacyTLFUpgrade = class LegacyTLFUpgrade extends TeamBase
  _type : () -> constants.sig_types.team.legacy_tlf_upgrade
  _type_v2 : () -> constants.sig_types_v2.team.legacy_tlf_upgrade

#--------------

exports.Settings = class Settings extends TeamBase
  _type : () -> constants.sig_types.team.settings
  _type_v2 : () -> constants.sig_types_v2.team.settings

#--------------
