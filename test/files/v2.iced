
{KeyManager} = require('kbpgp').kb
{prng} = require 'crypto'
{constants,errors,alloc,Eldest,Cryptocurrency} = require '../../'
{make_esc} = require 'iced-error'
{createHash} = require 'crypto'
{make_ids} = require '../../lib/base'
{pack,unpack} = require 'purepack'

new_uid = () -> prng(16).toString('hex')
new_username = () -> "u_" + prng(5).toString('hex')
new_device = () ->
sha256 = (x) -> createHash('SHA256').update(x).digest('hex')

#-------------

class User

  constructor : ({@uid, @username, @km}) ->
  @generate : (cb) ->
    esc = make_esc cb, "@generate"
    await KeyManager.generate {}, esc defer km
    uid = new_uid()
    username = new_username()
    cb null, new User { uid, username, km }
  to_json : () -> { @uid, @username }
  to_constructor_arg : ({seq_type} = {}) -> {
    user :
      local :
        username : @username
        uid : @uid
    host : 'keybase.io'
    sig_eng : @km.make_sig_eng()
    seq_type : seq_type
  }


#-------------

class Chain
  constructor : ({@user}) -> @links = []
  prev : () -> @links[-1...][0]
  push : (l) -> @links.push l
  copy : () -> new Chain { @user, links : [].concat(@links) }

  to_constructor_arg : (opts = {}) ->
    arg = @user.to_constructor_arg(opts)
    if (p = @prev())? then p.populate_next arg
    else
      arg.seqno = 0
      arg.prev = null
    arg

  to_btc_constructor_arg : (opts) ->
    ret = @to_constructor_arg(opts)
    ret.cryptocurrency = {
      address: "1BjgMvwVkpmmJ5HFGZ3L3H1G6fcKLNGT5h"
      type: "bitcoin"
    }
    ret

#-------------

class LinkV2
  constructor : ({@inner, @armored, @raw, @id, @short_id, @outer}) ->
  populate_next : (arg) ->
    arg.seqno = @inner.obj.seqno+1
    arg.prev = @chain_link_id()
  chain_link_id : () -> sha256 @outer
  full_type : () -> @inner.obj.body.type
  prev : () -> @inner.obj.prev

  verify : ({chain, opts}, cb) ->
    carg = chain.user.to_constructor_arg(opts)
    verifier = alloc @full_type(), carg
    varg = { @armored, skip_ids : true, make_ids : true, inner : @inner.str }
    await verifier.verify_v2 varg, defer err
    cb err

#-------------

chain = null
user = null

#-------------

exports.init = (T,cb) ->
  await User.generate T.esc(defer(u), cb)
  user = u
  chain = new Chain { user : u }
  cb()

#-------------

exports.gen_1 = (T,cb) ->
  arg = chain.to_constructor_arg()
  eldest = new Eldest arg
  await eldest.generate_v2 T.esc(defer(out), cb)
  link = new LinkV2 out
  chain.push link
  cb()

#-------------

check_valid_link = ({T, chain, link, i}, cb) ->
  link.verify { chain }, cb

check_valid_linkage = ({T, curr, prev}, cb) ->
  err = if not(prev) and not curr.prev() then null
  else if not(prev) or not curr.prev() then new Error "got nil/non-nil clash in checking for linkage"
  else if (a = prev.chain_link_id()) is (b = curr.prev()) then null
  else new Error "bad linkage: #{a} != #{b}"
  cb err

#-------------

check_valid_chain = ({T, chain}, cb) ->
  esc = make_esc cb, "check_valid_chain"
  for link, i in chain.links
    await check_valid_link {T, chain, link, i}, esc defer()
    await check_valid_linkage { T, curr : link, prev : chain.links[i-1] }, esc defer()
  cb null

#-------------

exports.check_chain_1 = (T,cb) ->
  check_valid_chain {T, chain}, cb

#-------------

exports.gen_2 = (T,cb) ->
  arg = chain.to_btc_constructor_arg()
  btc = new Cryptocurrency arg
  await btc.generate_v2 T.esc(defer(out), cb)
  link = new LinkV2 out
  chain.push link
  cb()

#-------------

exports.check_chain_2 = (T,cb) ->
  check_valid_chain {T, chain}, cb

#-------------

exports.gen_3 = (T,cb) ->
  arg = chain.to_btc_constructor_arg()
  arg.revoke = { sig_id :  "aabb" }
  btc = new Cryptocurrency arg
  await btc.generate_v2 T.esc(defer(out), cb)
  link = new LinkV2 out
  chain.push link
  cb()

#-------------

exports.check_chain_3 = (T,cb) ->
  check_valid_chain {T, chain}, cb

#-------------

forge_bad_link = ({link,h1,h2}, cb) ->
  esc = make_esc cb, "forge_bad_link"
  await link._v_generate {}, esc defer()
  await link.generate_json { version : 2}, esc defer s, o
  inner = { str : s, obj : o }
  if h1? then h1 { inner }
  await link.generate_outer {inner }, esc defer outer
  if h2? then outer = h2 { inner, outer }
  await link.sig_eng.box outer, esc defer {pgp, raw, armored}
  {short_id, id} = make_ids raw
  out = { pgp, id, short_id, raw, armored, inner, outer}
  cb null, out

#-------------

exports.check_bad_type_1 = (T,cb) ->
  arg = chain.to_btc_constructor_arg()

  btc = new Cryptocurrency arg
  h1 = ({inner}) -> inner.obj.body.type = "eldest"
  await forge_bad_link { link : btc, h1 }, T.esc(defer(out), cb)
  link = new LinkV2 out
  await check_valid_link { T, chain, link }, defer err
  T.assert err?, "should get a verification failure"
  T.equal err.toString(), "Error: Wrong signature type; got 'eldest' but wanted 'cryptocurrency'", "right error text"
  cb()

#-------------

check_bad_link = (T,arg,f,msg,cb) ->
  arg or= chain.to_btc_constructor_arg()
  btc = new Cryptocurrency arg
  out = null
  h2 = ({outer}) ->
    o = unpack outer
    f o
    pack o
  await forge_bad_link { link : btc, h2 }, T.esc(defer(out), cb)
  link = new LinkV2 out
  await check_valid_link { T, chain, link }, defer err
  T.assert err?, "should get a verification failure"
  # Sometimes we need late binding of what the error message will be
  # (as a function of what f does above), so use this hack.
  if typeof(msg) is 'function' then msg = msg()
  T.equal err.toString(), msg, "right error"

  cb()

#-------------

exports.check_bad_type_2 = (T,cb) ->
  f = (o) -> o[4] = constants.sig_types_v2.subkey
  check_bad_link T, null, f, "Error: Type mismatch: 12 != 6", cb

#-------------

exports.check_bad_type_3 = (T,cb) ->
  arg = chain.to_btc_constructor_arg()
  arg.revoke = { sig_id : "aabb" }
  f = (o) -> o[4] = constants.sig_types_v2.cryptocurrency
  check_bad_link T, arg, f, "Error: Type mismatch: 6 != 10", cb

#-------------

exports.check_bad_version = (T,cb) ->
  f = (o) -> o[0] = 1
  check_bad_link T, null, f, "Error: Bad version: 1 != 2", cb

#-------------

exports.check_bad_hash = (T,cb) ->
  msg = null
  f = (o) ->
    msg = "Error: hash mismatch: #{o[2].toString('hex')} != #{o[3].toString('hex')}"
    o[3] = o[2]
  msg_fn = () -> msg
  check_bad_link T, null, f, msg_fn, cb

#-------------

exports.check_bad_seqno = (T,cb) ->
  f = (o) -> o[1]++
  msg = "Error: wrong seqno: 4 != 3"
  check_bad_link T, null, f, msg, cb

#-------------

exports.check_bad_seq_type = (T,cb) ->
  f = (o) -> o[5] = constants.seq_types.SEMIPRIVATE
  msg = "Error: wrong seq type: 3 != 1"
  check_bad_link T, null, f, msg, cb

#-------------

exports.check_bad_prev = (T,cb) ->
  msg = null
  f = (o) ->
    msg = "Error: wrong prev: #{o[3].toString('hex')} != #{o[2].toString('hex')}"
    o[2] = o[3]
  msg_fn = () -> msg
  check_bad_link T, null, f, msg_fn, cb

#-------------

exports.semiprivate_link = (T,cb) ->
  esc = make_esc cb, "semiprivate_link"
  semipriv_chain = new Chain { user }
  arg = semipriv_chain.to_constructor_arg({seq_type : constants.seq_types.SEMIPRIVATE})
  eldest = new Eldest arg
  await eldest.generate_v2 esc defer out
  T.equal out.inner.obj.seq_type, constants.seq_types.SEMIPRIVATE, "right inner seqtype"
  T.equal unpack(out.outer)[5], constants.seq_types.SEMIPRIVATE, "right outer seqtype"
  link = new LinkV2 out
  semipriv_chain.push link
  await check_valid_chain {T, chain: semipriv_chain}, esc defer()
  cb null

#-------------
