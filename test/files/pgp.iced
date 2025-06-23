{alloc,Sibkey,Track} = require '../../'

kbpgp = require('kbpgp')
{EncKeyManager,KeyManager,kb} = kbpgp

{make_esc} = require 'iced-error'
{new_sig_arg, new_uid, new_username} = require './util'
pgp_utils = require('pgp-utils')
{json_stringify_sorted} = pgp_utils.util

{OnePassSignature} = require '../../node_modules/kbpgp/lib/openpgp/packet/one_pass_sig'
{Compressed} = require '../../node_modules/kbpgp/lib/openpgp/packet/compressed'
{Literal} = require '../../node_modules/kbpgp/lib/openpgp/packet/literal'
{Signature, CreationTime, Issuer} = require '../../node_modules/kbpgp/lib/openpgp/packet/signature'
{SHA512,SHA256} = kbpgp.hash
{SignatureEngine,Burner} = kbpgp
{Message} = kbpgp.processor

# Making sure KBPGP is not vulnerable to CVE-2025-47934, which was a critical
# message spoofing bug in OpenPGP.js
#
# https://github.com/openpgpjs/openpgpjs/security/advisories/GHSA-8qff-qr5q-5pr8

spoof_47934 = ({ sig, new_msg }, cb) ->
  esc = make_esc cb

  C = kbpgp.const.openpgp

  [err, decoded] = kbpgp.armor.decode sig
  if err then return cb err
  [err, packets] = kbpgp.parser.parse decoded.body
  if err then return cb err

  # keybase-proofs KBPGP signatures look like this:
  #
  # Compressed packet
  #  | One-Pass signature
  #  | Literal (with json body)
  #  | Signature

  # In order to trigger the bug in CVE-2025-47934, we need an uncompressed
  # sequence of One-Pass+Literal+Signature, followed by a compressed block. The
  # compressed block following a valid signed literal tricks OpenPGP.js into
  # presenting compressed literal as verified data.

  # Step 1: Parse message and inflate the single compressed block.
  msg = new Message { }
  await msg._parse decoded.body, esc defer packets
  if packets.length != 1 or packets[0].tag != C.packet_tags.compressed
    return cb new Error 'Expected 1 compressed packet'

  await packets[0].inflate esc defer inflated

  # Step 2: construct a new Compressed block with "new_msg".
  mal_lit = new Literal({ format: C.literal_formats.binary, data: Buffer.from(new_msg) })
  await mal_lit.write esc defer mal_lit_pkt
  malicious_payload = new Compressed { algo : C.compression.none, inflated : mal_lit_pkt }
  await malicious_payload.write esc defer malicious_out

  # Use inflated original data from step 1 and append "malicous" compressed
  # block to it. Create a PGP armored string.
  out_packets = [ inflated, malicious_out ]
  bad_armor = kbpgp.armor.encode(C.message_types.generic, Buffer.concat(out_packets))
  cb null, bad_armor

exports.fake_reverse_sig = (T,cb) ->
  esc = make_esc cb
  uid = new_uid()
  username = new_username()
  userid = "#{username} <#{username}@keybase.io>"
  await KeyManager.generate { nbits: 768, nsubs: 1, userid }, esc defer elder1
  await elder1.sign {}, esc defer()

  await KeyManager.generate { nbits: 768, nsubs: 1, userid }, esc defer sib1
  await sib1.sign {}, esc defer()

  arg = new_sig_arg { km : elder1 }
  arg.sibkm = sib1
  obj = new Sibkey arg
  await obj.generate_versioned { }, esc defer out1
  sib1_reverse_sig = out1.inner.obj.body.sibkey.reverse_sig

  await sib1.export_pgp_public {}, esc defer sib1_public_armored
  sib1 = null

  await KeyManager.generate { nbits: 768, nsubs: 1, userid }, esc defer elder2
  await elder2.sign {}, esc defer()

  # Assume owner of elder2 only has access to sib1 public key.
  await KeyManager.import_from_armored_pgp { raw : sib1_public_armored, opts: {} }, defer err, sib1_public

  # Geneate Sibkey proof, but spoof the reverse sig (because we don't have access to sib1 here).
  arg = new_sig_arg { km : elder2 }
  arg.sibkm = sib1_public
  obj = new Sibkey arg
  v_gen = obj._v_generate
  obj._v_generate = (opts, cb) ->
    esc = make_esc cb
    obj =
      reverse_sig: null
      kid: sib1_public.get_ekid().toString('hex')
    @set_new_key_section obj
    await @generate_json { version : opts.version }, esc defer new_msg
    await spoof_47934 { sig : sib1_reverse_sig, new_msg }, esc defer armored
    obj.reverse_sig = armored
    cb null
  await obj.generate_versioned { }, esc defer out2

  # CHECKING:
  typ = out2.inner.obj.body.type
  obj2 = alloc typ, arg
  varg = { armored : out2.armored, skip_ids : true, make_ids : true, inner : out2.inner.str }
  await obj2.verify varg, defer err
  T.assert err?, "got an error during verification"
  T.assert err?.message?.indexOf("Expected only one pgp literal; got 2") >= 0, "got the right message"

  cb null

exports.fake_track = (T,cb) ->
  esc = make_esc cb
  uid = new_uid()
  username = new_username()
  userid = "#{username} <#{username}@keybase.io>"
  await KeyManager.generate { nbits: 768, nsubs: 1, userid }, esc defer elder
  await elder.sign {}, esc defer()

  # Elder makes a legit Track proof with a signature.
  arg = new_sig_arg { km : elder }
  arg.track = { username: 'legit username' }
  obj = new Track arg
  await obj.generate_versioned { }, esc defer out
  typ = out.inner.obj.body.type

  # Consider an attacker that does not have access to elder privat key, only
  # public key.
  await elder.export_pgp_public {}, esc defer elder_pub_armored
  await KeyManager.import_from_armored_pgp { raw : elder_pub_armored, opts: {} }, defer err, elder_pub

  # Verify proof with public key.
  arg2 = new_sig_arg { km : elder_pub }
  arg2.user = arg.user
  obj2 = alloc typ, arg2
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str }
  await obj2.verify varg, esc defer()

  # Bug 47934 would allow us to spoof the message for legit Track signature.
  new_msg = Object.assign {}, out.inner.obj
  # Make sure we are changing the right field
  T.equal new_msg.body.track.username, "legit username"
  new_msg.body.track.username = "malicious username"
  new_msg = json_stringify_sorted(new_msg)
  await spoof_47934 { sig : out.armored, new_msg : Buffer.from(new_msg) }, esc defer armored

  # Verify again.
  varg = { armored : armored, skip_ids : true, make_ids : true, inner : new_msg }
  await obj2.verify varg, defer err
  T.assert err?, "got an error during verification"
  T.assert err?.message?.indexOf("Expected only one pgp literal; got 2") >= 0, "got the right message"

  cb null
