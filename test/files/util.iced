{prng} = require 'crypto'
{constants} = require '../..'
pgp_utils = require('pgp-utils')
{unix_time} = pgp_utils.util
{KeyManager} = require('kbpgp').kb
{make_esc} = require 'iced-error'

exports.new_uid = new_uid = () -> Buffer.concat([ prng(15), Buffer.from([0x19])]).toString('hex')
exports.new_sig_id = new_sig_id = () -> Buffer.concat([ prng(32), Buffer.from([0x22])]).toString('hex')
exports.new_username = new_username = () -> "u_" + prng(5).toString('hex')
exports.new_payload_hash = new_payload_hash = () -> prng(32).toString('hex')

exports.skip = 1

exports.new_sig_arg = new_sig_arg = ({km}) ->
  arg =
    user :
      local :
        uid : new_uid()
        username : new_username()
    host : "keybase.io"
    sig_eng : km.make_sig_eng()
    seqno : 0
    seq_type : constants.seq_types.PUBLIC
    prev : null

exports.new_sig_arg_v3 = new_sig_arg_v3 = ({km, mk_prev, eldest_seqno, seqno, parent_chain_tail}) ->
  arg =
    user :
      local :
        uid : new_uid()
        eldest_seqno : eldest_seqno or 1
    sig_eng : km.make_sig_eng()
    seqno : seqno or 7
    prev : (if mk_prev then prng(32) else null)
    parent_chain_tail : (parent_chain_tail or {
      hash : prng(32)
      seqno : 10
      chain_type : constants.seq_types.SEMIPRIVATE
    })
    client :
      name : "go darwin"
      version : "4.1.0"
    ctime : unix_time()
    ignore_if_unsupported : false
    merkle_root :
      ctime : unix_time() - 10
      hash_meta : "db951e27435ec22ac266f6880dcedeb6f57cbed28f014a0f774a54b932fcb153"
      seqno : 4768147

exports.new_km_and_sig_arg = (opts, cb) ->
  esc = make_esc cb
  await KeyManager.generate {}, esc defer km
  arg = new_sig_arg { km }
  cb null, arg
