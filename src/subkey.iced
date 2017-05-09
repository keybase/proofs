
{Base} = require './base'
{constants} = require './constants'
{make_esc} = require 'iced-error'
pgp_utils = require('pgp-utils')
{json_stringify_sorted,unix_time,streq_secure} = pgp_utils.util

#==========================================================================

a_json_parse = (x, cb) ->
  ret = err = null
  try ret = JSON.parse x
  catch e then err = e
  cb err, ret

json_cp = (x) -> JSON.parse JSON.stringify x

#==========================================================================

exports.SubkeyBase = class SubkeyBase extends Base

  get_new_key_section : () -> null
  set_new_key_section : (s) ->
  get_new_km : () -> null
  get_key_field : () -> null
  need_reverse_sig : () -> false
  _optional_sections : () -> super().concat(["device"])

  _v_pgp_details_dest : (body) -> body[@get_key_field()]
  _v_pgp_km : -> @get_new_km()

  _v_generate : (opts, cb) ->
    esc = make_esc cb, "_v_generate"
    if not @get_new_key_section()? and @get_new_km()?
      obj = { reverse_sig: null }
      obj[@sibkid_slot()] = @get_new_km().get_ekid().toString('hex') if @sibkid_slot()?
      obj.parent_kid = @parent_kid if @parent_kid?
      @set_new_key_section obj
      if @get_new_km().can_sign()
        eng = @get_new_km().make_sig_eng()
        await @generate_json { version : opts.version }, esc defer msg
        await eng.box msg, esc defer { armored, type }
        obj.reverse_sig = armored
    cb null

  _v_customize_json : (ret) ->
    ret.body[@get_key_field()] = @get_new_key_section()
    ret.body.device = @device if @device?

  sibkid_slot : () -> "kid"

  _match_json : (outer, inner) ->
    outer = json_cp outer
    @_clear_reverse_sig(outer)
    a = json_stringify_sorted outer
    b = json_stringify_sorted inner
    err = null
    unless streq_secure a, b
      err = new Error "Reverse sig json mismatch: #{a} != #{b}"
    return err

  _v_check : ({json}, cb) ->
    esc = make_esc cb, "SubkeyBase::_v_check"
    await super { json }, esc defer()
    await @reverse_sig_check { json, new_km: @get_new_km() }, esc defer()
    cb null

  _get_reverse_sig : (json) ->
    json?.body?[@get_key_field()]?.reverse_sig
  _get_new_sibkid : (json) ->
    json?.body?[@get_key_field()]?[@sibkid_slot()]
  _clear_reverse_sig : (outer) ->
    # body.sibkey.reverse_sig should be the only field different between the two
    outer.body[@get_key_field()].reverse_sig = null

  reverse_sig_check : ({json, new_km, subkm}, cb) ->

    # For historical reasons, some people call 'new_km' 'subkm'
    new_km or= subkm

    esc = make_esc cb, "SubkeyBase::reverse_sig_check"
    err = null
    if (sig = @_get_reverse_sig(json))? and new_km?
      eng = new_km.make_sig_eng()
      await eng.unbox sig, esc defer raw
      await a_json_parse raw, esc defer payload
      rsk = new_km.get_ekid().toString('hex')
      if (err = @_match_json json, payload)? then # noop
      else if not streq_secure (a = @_get_new_sibkid(json)), (b = rsk)
        err = new Error "Sibkey KID mismatch: #{a} != #{b}"
      else
        @reverse_sig_kid = rsk
    else if @need_reverse_sig json
      err = new Error "Need a reverse sig, but didn't find one"
    cb err

  constructor : (obj) ->
    @device = obj.device
    super obj

#==========================================================================

exports.Subkey = class Subkey extends SubkeyBase

  get_key_field : () -> "subkey"
  _type_v2 : () -> constants.sig_types_v2.subkey

  get_new_key_section : () -> @subkey
  set_new_key_section : (s) -> @subkey = s
  get_new_km : () -> @subkm

  _type : () -> constants.sig_types.subkey
  _required_sections : () -> super().concat(["subkey"])

  constructor : (obj) ->
    @subkey = obj.subkey
    @subkm = obj.subkm
    @parent_kid = obj.parent_kid
    super obj

#==========================================================================
