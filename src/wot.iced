{Base} = require './base'
{constants} = require './constants'
{make_esc} = require 'iced-error'
pgp_utils = require('pgp-utils')
{json_stringify_sorted,unix_time,streq_secure} = pgp_utils.util
schema = require './schema3'

#==========================================================================

exports.Attest = class Attest extends Base

  constructor : (obj) ->
    @wot = obj.wot
    super obj

  _v_stub_paths : () -> [ "body.wot_attest" ]
  _type : () -> constants.sig_types.wot.attest

  _type_v2 : (revoke_flag) ->
    if @revoke? or revoke_flag then constants.sig_types_v2.wot.attest_with_revoke
    else constants.sig_types_v2.wot.attest

  _v_check : ({json}, cb) ->
    obj = json.body.wot_attest

    proof_schema = schema.dict({
      check_data_json : schema.or([
        schema.dict({name : schema.string(),   username : schema.string() }),
        schema.dict({domain : schema.string(), protocol : schema.string() })
      ])
      state : schema.int()
      proof_type : schema.int()
    })

    schm = schema.dict({
      user : schema.dict({
        username : schema.string()
        uid : schema.uid().convert()
        eldest_seqno : schema.int()
        last_seqno : schema.int()
        eldest_kid : schema.kid().convert()
      })
      confidence : schema.dict({
        proofs : schema.array(proof_schema).optional()
        vouched_by : schema.array(schema.uid().convert()).optional()
        keybase_username : schema.string_enum(["audio","video","email","other_chat","in_person"]).optional()
        other : schema.string().optional()
        keybase_history : schema.int().optional()
      })
      failing_proofs : schema.array(proof_schema).optional()
      attestation : schema.array(schema.string())
    })
    cb schm.check(obj)

   _v_customize_json : (ret) ->
    ret.body.wot_attest = t if (t = @wot.attest)?

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