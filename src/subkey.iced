
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

match_json : (outer, inner) ->
  outer = json_cp outer
  # body.sibkey.reverse_sig should be the only field different between the two
  outer?.body?.sibkey?.reverse_sig = null
  outer?.body?.subkey?.reverse_sig = null
  a = json_stringify_sorted outer
  b = json_stringify_sorted inner
  err = null
  unless streq_secure a, b
    err = new Error "Reverse sig json mismatch: #{a} != #{b}"
  return err

#==========================================================================

exports.DelegateKey = class DelegateKey extends Base

  _v_generate : (opts, cb) ->
    esc = make_esc cb, "_v_generate"
    _v_generate_stanza { which : 'sub' }
    _v_generate_stanza { which : 'sib' }
    await _v_generate_sign { which : 'sub' }, esc defer()
    await _v_generate_sign { which : 'sib' }, esc defer()
    cb null

  _v_generate_stanza : ({which}) ->
    if @[which]?.km?
      obj =
        kid : @[which].km.get_ekid().toString('hex')
        reverse_sig: null
      obj.parent_kid = @parent_kid if @parent_kid? and which is 'sub'
      @[which].stanza = obj

  _v_generate_sign : ({which}, cb) ->
    esc = make_esc cb, "_v_generate_sign"
    if (km = @[which]?.km)? and km.can_sign()
      msg = @json()
      eng = km.make_sig_eng()
      await eng.box msg, esc defer { armored, type }
      @[which].stanza.reverse_sig = armored
    cb null

  _json : () ->
    ret = super {}
    ret.body.subkey = z if (z = @sub.stanza)?
    ret.body.sibkey = z if (z = @sib.stanza)?
    ret.body.device = @device if @device?
    return ret

  _v_check : ({json}, cb) ->
    esc = make_esc cb, "SubkeyBase::_v_check"
    await super { json }, esc defer()
    await @reverse_sig_check { json, km : @sib.km }, esc defer()
    cb null

  reverse_sig_check : ({json, km}, cb) ->
    esc = make_esc cb, "SubkeyBase::reverse_sig_check"
    err = null
    if not json?.body?.sibkey? then # noop
    else if (sig = json.body.sibkey.reverse_sig)? and km?
      eng = km.make_sig_eng()
      await eng.unbox sig, esc defer raw
      await a_json_parse raw, esc defer payload
      rsk = km.get_ekid().toString('hex')
      if (err = @_match_json json, payload)? then # noop
      else if not streq_secure (a = json?.body?.sibkey?.kid), (b = rsk)
        err = new Error "Sibkey KID mismatch: #{a} != #{b}"
      else
        @reverse_sig_kid = rsk
    else
      err = new Error "Need a reverse sig, but didn't find one"
    cb err

  constructor : (obj) ->
    @sub = { km : obj.subkm }
    @sib = { km : obj.sibkm }
    @device = obj.device
    super obj

  _type : () -> constants.sig_types.sibkey

#==========================================================================
