{Base} = require './base'
{constants} = require './constants'
{make_esc} = require 'iced-error'
pgp_utils = require('pgp-utils')
{json_stringify_sorted,unix_time,streq_secure} = pgp_utils.util
schema = require './schema3'

#==========================================================================

exports.Vouch = class Vouch extends Base

  constructor : (obj) ->
    @wot = obj.wot
    super obj

  _v_stub_paths : () -> [ "body.wot_vouch" ]
  _type : () -> constants.sig_types.wot.vouch

  _type_v2 : (revoke_flag) ->
    if @revoke? or revoke_flag then constants.sig_types_v2.wot.vouch_with_revoke
    else constants.sig_types_v2.wot.vouch

  _v_check : ({json}, cb) ->
    obj = json.body.wot_vouch
    if not obj? then return cb null

    proof_schema = schema.or([
      schema.dict({
        proof_type : schema.int(), # keybase1.ProofType
        name : schema.string(),
        username : schema.string()
      }),
      schema.dict({
        proof_type : schema.int(),
        protocol : schema.string(),
        hostname : schema.string()
      }),
      schema.dict({
        proof_type : schema.int(),
        protocol : schema.string(),
        domain : schema.string()
      })
    ])

    schm = schema.dict({
      user : schema.dict({
        username : schema.string()
        uid : schema.uid().convert()
        eldest : schema.dict({
          seqno : schema.int()
          kid : schema.kid().convert()
        })
        seq_tail : schema.dict({
         seqno : schema.int()
         sig_id : schema.sig_id().convert()
         payload_hash : schema.hash().convert()
        })
      })
      confidence : schema.dict({
        username_verified_via : schema.string_enum(["in_person", "proofs", "video", "audio", "other_chat", "familiar", "other"]).optional()
        proofs: schema.array(proof_schema).optional()
        other : schema.string().optional()
      })
      failing_proofs : schema.array(proof_schema).optional()
      vouch_text : schema.array(schema.string())
    })
    err = schm.check(obj)
    if err?
      cb err
    
    for text in obj.vouch_text
      if text.length > 700
        cb E.make("vouch_text too long")

    if obj.confidence.other?.length > 90
        cb E.make("confidence.other too long")

   _v_customize_json : (ret) ->
    ret.body.wot_vouch = t if (t = @wot?.vouch)?

#==========================================================================

exports.React = class React extends Base

  constructor : (obj) ->
    @wot = obj.wot
    super obj

  _v_stub_paths : () -> [ "body.wot_react" ]
  _type : () -> constants.sig_types.wot.react

  _type_v2 : (revoke_flag) -> constants.sig_types_v2.wot.react

  _v_check : ({json}, cb) ->
    obj = json.body.wot_react
    schm = schema.dict({
      sig_id : schema.sig_id().convert()
      reaction : schema.string_enum(["accept", "reject"])
    })
    cb schm.check(obj)

   _v_customize_json : (ret) ->
    ret.body.wot_react = t if (t = @wot.react)?

#==========================================================================
