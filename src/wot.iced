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

body =  {
   "client" : {
      "version" : "5.2.0",
      "name" : "keybase.io go client"
   },
   "prev" : "afccadcae75cbda35e5d463b0b8eff766c5d66f1b39722f9c93c8a3d2544b32c",
   "tag" : "signature",
   "expire_in" : 504576000,
   "seqno" : 681,
   "body" : {
      "version" : 2,
      "type" : "wot_attest_with_revoke",
      "key" : {
         "host" : "keybase.io",
         "uid" : "dbb165b7879fe7b1174df73bed0b9500",
         "eldest_kid" : "01013ef90b4c4e62121d12a51d18569b57996002c8bdccc9b2740935c9e4a07d20b40a",
         "kid" : "01203073f406c94fc932c9e2e434631c7626bb0a0aa12e526dc1bec270e7e903f4ec0a",
         "username" : "max"
      },
      "merkle_root" : {
         "hash" : "02ee4d0efc9ad56e345d30f954b1d18fd0deff35611473326124f8b9c10f94af429e567f753ece952dd6f7190bb46a51ac83fceffddde6068045583bfb9ca2b0",
         "hash_meta" : "fb594986ac735bd49a66fe4eb7b7e29d8ca99517c37f7de62125d0102dcb87f9",
         "seqno" : 14144837,
         "ctime" : 1578519663
      },
      "revoke" : {
         "sig_ids" : [ # revoke by sig IDs so we can scrub, eventually, what the actual link was.
            "2fb7d9eaffd97097ebee09258e27fb89ee7048501b8a818040cf58152ea557590f"
         ],
      },
      "attest_hash" : "4945b2c25aaf805554e8d6ac28760b0b50c3c46b4b6fe548e48a38aef6823c59",
      "ctime" : 1578519669
   }
}

# attest = {
#    "user" : {       # this is a roll-up of what's currently in a tracking statement, for brevity's sake
#       "username" : "betaveros",
#       "id" : "11c37ef3432f708638c7262648dba919",
#       "eldest_seqno" : 10,
#       "eldest_kid" : "01010aa8faa627fb234cf51c7cb32ccbe9fbca45ff07faeb2a2d85e0aab1958bb2480a",
#       "last_seqno" : 20
#    },
#    "confidence" : {  # can leave empty fields out
#       "proofs" : [   # these formats match what's currently in a tracking statement
#          {
#             "check_data_json" : {
#                "name" : "github",
#                "username" : "betaveros"
#              },
#              "state" : 1,
#              "proof_type" : 2
#          },
#          {
#             "check_data_json" : {
#                "name" : "reddit",
#                "username" : "betaveros"
#              },
#              "state" : 1,
#              "proof_type" : 2
#           }
#       ],
#       "vouched_by" : [ # uids who vouched for this user
#          "da121be06bde32f6b5d2ae03b8b50019",
#          "93b3c12c121f396e1aee9d6e7eb6cf19"
#       ],
#       "keybase_username" : "in_person",   # one of [ "audio", "video", "email", "other_chat" ] or can be null
#       "keybase_history" : false,          # true if they have a long keybase history
#       "other" : "foobie doobie shroobie", # other
#    },
#    "failing_proofs" : [ # only list the advertised non-revoked social proofs that are currently failing; the rest are assumed to work
#       {
#          "check_data_json" : {
#             "name" : "twitter",
#             "username" : "betaveros"
#           },
#           "state" : 3,
#           "proof_type" : 2
#        }
#    ],
#    "attestion" : [ # the meat of it
#       "I have worked with Cecile at Keybase since 2015, where she is a Product Designer.",
#    ],
# }
