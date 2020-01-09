{prng} = require 'crypto'
{expand_json,stub_json} = require '../../lib/expand'
triplesec = require('triplesec')
{SHA256} = triplesec.hash
pgp_utils = require('pgp-utils')
{katch,json_stringify_sorted} = pgp_utils.util
{KeyManager} = require('kbpgp').kb
{prng} = require 'crypto'
{constants,errors,alloc,Cryptocurrency} = require '../../'
{createHash} = require 'crypto'
{make_ids} = require '../../lib/base'
{make_esc} = require 'iced-error'
{errors} = require '../../lib/errors'

new_uid = () -> prng(15).toString('hex') + "19"
new_username = () -> "u_" + prng(5).toString('hex')
new_device = () ->
sha256 = (x) -> createHash('SHA256').update(x).digest('hex')

make_expansions = (v) ->
  ret = {}
  hash = (o) ->
    s = json_stringify_sorted o
    (new SHA256).bufhash(Buffer.from(s, 'utf8')).toString('hex')
  for e in v
    ret[hash(e)] = e
  return ret

exports.happy = (T,cb) ->
  expansion_vals = [ ["a","b","c"], 300 ]
  expansions = make_expansions expansion_vals
  h = Object.keys(expansions)

  json = {
    a : 10
    b : "hi"
    c : d : e : h[0]
    f : [1,2,3]
    g : [
      { h : h[1] }
    ]
    i : h
  }
  res = expand_json { json, expansions }
  json.c.d.e = expansion_vals[0]
  json.g[0].h = expansion_vals[1]
  json.i[0] = expansion_vals[0]
  json.i[1] = expansion_vals[1]
  T.equal json, res, "worked"
  cb null

exports.sad1 = (T,cb) ->
  expansion_vals = [ ["a","b","c"], 300 ]
  expansions = make_expansions expansion_vals
  h = Object.keys(expansions)

  tests = [
    { expansions : { "a" : "10" }, json : 10, err : "bad hash" }
    { expansions : {}, json : 10, err : "hashcheck failure" }
    { expansions, json : 10, err : "Did not find expansion for" }
    { expansion : make_expansions(["💩"]), json : 10, err : "non-ASCII" }
  ]
  tests[1].expansions[h[0]] = ["a","b"]

  for t in tests
    try
      expand_json t
    catch e
      T.assert e?, "error for case #{JSON.stringify t}"
      T.assert e.toString().indexOf(t.err) >= 0, "found #{t.err}"

  cb null

exports.check_unstub_expand = (T,cb) ->
  json = {
    a : b : c : { z : 1, y : 2, w : 3}
    d : e : f : true
    g : h : false
  }
  orig = JSON.parse JSON.stringify json
  expansions = {}
  stub_json { json, expansions, path : "a.b.c" }
  stub_json { json, expansions, path : "d.e"}

  expanded = expand_json { expansions, json }
  T.equal orig, expanded, "got the right value out"

  cb null


exports.stubbed_chainlink = (T,cb) ->
  esc = make_esc cb, "@generate"
  await KeyManager.generate {}, esc defer km
  arg =
    user :
      local :
        username : new_username()
        uid : new_uid()
    host : "keybase.io"
    sig_eng : km.make_sig_eng()
    seq_type : constants.seq_types.PUBLIC
    cryptocurrency :
      address: "1BjgMvwVkpmmJ5HFGZ3L3H1G6fcKLNGT5h"
      type: "bitcoin"
    seqno : 1
    prev : null
    stub_paths : [ "body.cryptocurrency" ]
  btc = new Cryptocurrency arg
  await btc.generate_v2 esc defer out

  verifier = alloc out.inner.obj.body.type, arg
  varg = { armored : out.armored, skip_ids : true, make_ids : true, inner : out.inner.str, expansions : out.expansions}
  await verifier.verify_v2 varg, esc defer()
  for k,v of out.expansions
    v.foo = "bar"
    out.expansions[k] = v
  await verifier.verify_v2 varg, defer err
  T.assert err?, "failed to destub"
  T.assert (err instanceof errors.ExpansionError), "right kind of error"
  T.assert (err.toString().indexOf("hashcheck failure in stub import") >= 0), "right error message"
  cb null
