{alloc,wot,constants} = require '../../'
{EncKeyManager,KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'
{new_uid,new_km_and_sig_arg,new_sig_id,new_payload_hash} = require './util'
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util
{unpack} = require 'purepack'

exports.wot_vouch_happy = (T,cb) ->
  esc = make_esc cb
  await new_km_and_sig_arg {}, esc defer me
  await new_km_and_sig_arg {}, esc defer them
  sig_id = "24786764ee0861eb134925fe967c03975fba5df02edfabcf4048c71d8cb8623c0f"
  me.wot =
    vouch :
      user :
        username : them.user.local.username
        uid : them.user.local.uid
        eldest:
          kid : them.sig_eng.km.key.ekid().toString('hex')
          seqno : 1
        seq_tail :
          seqno : 20
          sig_id : new_sig_id()
          payload_hash : new_payload_hash()
      confidence :
        username_verified_via : "audio"
        other : "lorem ipsum"
        proofs : [ sig_id, sig_id]
      failing_proofs : [ sig_id, sig_id ]
      vouch_text : [
        "darn rootin tootin"
      ]
  obj = new wot.Vouch me
  await obj.generate_v2 esc(defer(out)), {dohash:true}
  hsh = out.inner.obj.body.wot_vouch
  T.assert hsh?, "hash was there"
  T.equal hsh.length, 64, "64-byte hex string"
  T.assert out.expansions[hsh]?.obj?, "expansion was there"

  verifier = alloc out.inner.obj.body.type, me
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str, expansions : out.expansions, require_packet_hash :true}
  await verifier.verify_v2 varg, esc defer()

  me.wot =
    react :
      sig_id : new_sig_id()
      reaction : "accept"
  obj = new wot.React me
  await obj.generate_v2 esc(defer(out)), {dohash:true}
  verifier = alloc out.inner.obj.body.type, me
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str, expansions : out.expansions, require_packet_hash :true}
  await verifier.verify_v2 varg, esc defer()

  # try to revoke both with and without a replacement...
  me.revoke = { sig_ids : [ new_sig_id() ]}
  obj = new wot.Vouch me
  await obj.generate_v2 esc(defer(out)), {dohash:true}
  outer = unpack out.outer
  T.equal outer[4], constants.sig_types_v2.wot.vouch_with_revoke, "revoke picked up"

  me.wot = null
  obj = new wot.Vouch me
  await obj.generate_v2 esc(defer(out)), {dohash:true}
  outer = unpack out.outer
  T.equal outer[4], constants.sig_types_v2.wot.vouch_with_revoke, "revoke picked up"

  cb null
