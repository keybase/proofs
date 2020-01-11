{alloc,wot} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_uid,new_km_and_sig_arg} = require './util'
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util

exports.wot_attest_happy = (T,cb) ->
  esc = make_esc cb
  await new_km_and_sig_arg {}, esc defer me
  await new_km_and_sig_arg {}, esc defer them
  proof = {
    check_data_json :
      name : "reddit",
      username : "betaveros"
    state : 1,
    proof_type : 2
  }
  me.wot =
    attest :
      user :
        username : them.user.local.username
        uid : them.user.local.uid
        eldest_kid : them.sig_eng.km.key.ekid().toString('hex')
        last_seqno : 20
        eldest_seqno : 1
      confidence :
        vouched_by : (new_uid() for _ in [0...4])
        keybase_username : "audio"
        other : "lorem ipsum"
        proofs : [ proof, proof]
      failing_proofs : [ proof, proof ]
      attestation : [
        "darn rootin tootin"
      ]
  obj = new wot.Attest me
  await obj.generate_v2 esc defer out
  hsh = out.inner.obj.body.wot_attest
  T.assert hsh?, "hash was there"
  T.equal hsh.length, 64, "64-byte hex string"
  T.assert out.expansions[hsh]?.obj?, "expansion was there"

  verifier = alloc out.inner.obj.body.type, me
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str, expansions : out.expansions}
  await verifier.verify_v2 varg, esc defer()
  cb null

