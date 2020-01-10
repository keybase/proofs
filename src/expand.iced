parse3 = require './parse3'
pgp_utils = require('pgp-utils')
{katch,json_stringify_sorted} = pgp_utils.util
triplesec = require('triplesec')
{SHA256} = triplesec.hash
{ExpansionError} = require('./errors').errors
{prng} = require 'crypto'

#========================================================

check_expansions = ({expansions}) ->
  for k,v of expansions
    check_expansion_kv {k, v}

#========================================================

exports.hash_obj = hash_obj = (o) ->
  s = json_stringify_sorted o
  (new SHA256).bufhash(Buffer.from(s, 'utf8')).toString('hex')

#========================================================

check_expansion_kv = ({k,v}) ->
  if not parse3.is_hex(k, 32) then throw new ExpansionError "bad hash: #{k}"
  s = json_stringify_sorted v
  if not /^[\x20-\x7e]+$/.test(s) then throw new ExpansionError "JSON stub has non-ASCII"
  h = (new SHA256).bufhash(Buffer.from(s, 'utf8')).toString('hex')
  if k isnt h then throw new ExpansionError "hashcheck failure in stub import"

#========================================================

exports.expand_json = ({json, expansions}) ->
  expansions or= {}
  if Object.keys(expansions).length is 0 then return json
  check_expansions { expansions }

  found = {}

  xform = (o) ->
    if not o? then return o

    if typeof(o) is 'string' and (expansion = expansions[o])?
      found[o] = true
      return expansion

    if typeof(o) isnt 'object' then return o

    if Array.isArray(o)
      ret = []
      for v in o
        ret.push xform v
      return ret

    ret = {}
    for k,v of o
      ret[k] = xform v
    return ret

  json = xform json

  # All listen expansions have to be used, otherwise, there was an issue.
  for k of expansions when not found[k]
    throw new ExpansionError "Did not find expansion for #{k}"

  return json

#========================================================

json_at_path = ({json, path, repl}) ->
  components = path.split(/\./)
  prev = null
  last_component = null
  for c in components
    prev = json
    last_component = c
    json = json[c]
    if not json? then throw new Error "cannot find path #{path}"
  if repl?
    if not prev? or not last_component? then throw new ExpansionError "failed to replace at #{path}"
    prev[last_component] = repl
  return json

#-----------

exports.stub_json = ({json, expansions, path}) ->
  obj = json_at_path { json, path }
  obh = JSON.parse JSON.stringify obj
  obj.entropy = prng(16).toString('base64')
  h = hash_obj obj
  expansions[h] = obj
  json_at_path { json, path, repl : h }
  null

#========================================================

