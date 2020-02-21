{proof_type_to_string,constants} = require './constants'
pgp_utils = require('pgp-utils')
{trim,katch,akatch,bufeq_secure,json_stringify_sorted,unix_time,base64u,streq_secure} = pgp_utils.util
triplesec = require('triplesec')
{WordArray} = triplesec
{SHA256} = triplesec.hash
kbpgp = require 'kbpgp'
{make_esc} = require 'iced-error'
util = require 'util'
{base64_extract} = require './b64extract'
{errors,errsan} = require './errors'
purepack = require 'purepack'
{bufferify} = require './util'
{expand_json,stub_json} = require './expand'

#==========================================================================

exports.hash_sig = hash_sig = (sig_body) ->
  (new SHA256).bufhash(sig_body)

#------

add_ids = (sig_body, out) ->
  hash = hash_sig sig_body
  id = hash.toString('hex')
  short_id = sig_id_to_short_id hash
  out.id = id
  out.med_id = sig_id_to_med_id hash
  out.short_id = short_id

#------

exports.make_ids = make_ids = (sig_body) ->
  out = {}
  add_ids sig_body, out
  return out

#------

sig_id_to_med_id = (sig_id) -> base64u.encode sig_id

#------

sig_id_to_short_id = (sig_id) ->
  base64u.encode sig_id[0...constants.short_id_bytes]

#================================================================================

has_revoke = (o) ->
  if not o?.revoke? then false
  else if o.revoke.sig_id? then true
  else if (o.revoke.sig_ids?.length > 0) then true
  else if o.revoke.kid? then true
  else if (o.revoke.kids?.length > 0) then true
  else false

#================================================================================

proof_text_check_to_med_id = (proof_text_check) ->
  {med_id} = make_ids(Buffer.from proof_text_check, 'base64')
  med_id

#================================================================================

isString = (x) -> (typeof x is 'string') or (x instanceof String)
exports.cieq = cieq = (a,b) -> (a? and b? and (isString a) and (isString b) and (a.toLowerCase() is b.toLowerCase()))

#==========================================================================

compare_hash_buf_to_str = (b, s) ->
  if not(b)? and not(s)? then true
  else if not(b)? or not(s)? then false
  else bufeq_secure b, (Buffer.from s, 'hex')

#==========================================================================

class Verifier

  constructor : ({@armored, @id, @short_id, @skip_ids, @make_ids, @strict, @now, @critical_clock_skew_secs, @skip_clock_skew_check, @inner, @outer, @expansions, @assert_pgp_hash}, @sig_eng, @base) ->

  #---------------

  km : () -> @sig_eng.get_km()

  #---------------

  get_etime : () ->
    if @json.ctime? and @json.expire_in then (@json.ctime + @json.expire_in)
    else null

  #---------------

  verify : (cb) ->
    esc = make_esc cb, "Verifier::verfiy"
    await @_parse_and_process {@armored}, esc defer payload
    await @_check_json {payload, @expansions}, esc defer json_obj, json_str
    await @_check_ctime esc defer() unless @skip_clock_skew_check
    await @_check_expired esc defer()
    await @_check_version { v : 1 }, esc defer()
    cb null, json_obj, json_str

  #---------------

  verify_v2 : (cb) ->
    esc = make_esc cb, "Verifier::verfiy"
    await @_parse_and_process {@armored}, esc defer outer_raw
    inner_buf = Buffer.from @inner, 'utf8'
    await @_check_json {payload : inner_buf, @expansions}, esc defer json_obj, json_str
    await @_check_inner_outer_match { outer_raw, inner_obj : json_obj, inner_buf }, esc defer outer_obj
    await @_check_ctime esc defer() unless @skip_clock_skew_check
    await @_check_expired esc defer()
    await @_sanity_check_high_skip esc defer() if @json.high_skip?
    cb null, outer_obj, json_obj, json_str

  #---------------

  _check_inner_outer_match : ({outer_raw, inner_obj, inner_buf}, cb) ->
    esc = make_esc cb, "_check_inner_outer_match"
    await OuterLink.parse { raw : outer_raw }, esc defer outer
    err = if (a = outer.type) isnt (b = @base._type_v2(has_revoke(inner_obj.body)))
      new Error "Type mismatch: #{errsan a} != #{errsan b}"
    else if (a = outer.version) isnt (b = constants.versions.sig_v2)
      new Error "Bad version: #{errsan a} != #{errsan b}"
    else if (a = outer.version) isnt (b = inner_obj.body.version)
      new Error "Version mismatch: #{errsan a} != #{errsan b}"
    else if not bufeq_secure (a = outer.hash), (b = hash_sig(inner_buf))
      new Error "hash mismatch: #{a?.toString('hex')} != #{b?.toString('hex')}"
    else if (a = outer.seqno) isnt (b = inner_obj.seqno)
      err = new errors.WrongSeqnoError "wrong seqno: #{errsan a} != #{errsan b}"
      err.seqno = b
      err
    else if not compare_hash_buf_to_str (a = outer.prev), (b = inner_obj.prev)
      new Error "wrong prev: #{a?.toString('hex')} != #{errsan b}"
    else if (a = outer.get_seq_type()) isnt (b = (inner_obj.seq_type or constants.seq_types.PUBLIC))
      new Error "wrong seq type: #{errsan a} != #{errsan b}"
    else if (a = outer.get_ignore_if_unsupported()) isnt (b = (inner_obj.ignore_if_unsupported or false))
      new Error "wrong ignore_if_unsupported value: #{errsan a} != #{errsan b}"
    else if (a = outer.get_high_skip()?.seqno) isnt (b = (inner_obj.high_skip?.seqno))
      new errors.BadHighSkipError "wrong high_skip seqno: #{errsan a} != #{errsan b}"
    else if not compare_hash_buf_to_str (a = outer.get_high_skip()?.hash), (b = (inner_obj.high_skip?.hash))
      new errors.BadHighSkipError "wrong high_skip hash value: #{a?.toString('hex')} != #{errsan b}"
    else
      null
    cb err, outer

  #---------------

  _check_ids : (body, cb) ->
    {short_id, id} = make_ids body
    err = if not (@id? and streq_secure id, @id)
      new Error "Long IDs aren't equal; wanted #{errsan id} but got #{errsan @id}"
    else if not (@short_id? and streq_secure short_id, @short_id)
      new Error "Short IDs aren't equal: wanted #{errsan short_id} but got #{errsan @short_id}"
    else null
    cb err

  #---------------

  _get_now : () -> if @now? then @now else unix_time()
  _get_critical_clock_skew_secs : () -> @critical_clock_skew_secs or constants.critical_clock_skew_secs

  #---------------

  _check_ctime : (cb) ->
    now = @_get_now()
    unless @json.ctime?
      err = new Error "no ctime given"
    else
      diff = Math.abs(now - @json.ctime)
      if Math.abs(diff) > @_get_critical_clock_skew_secs()
        epoch = if now > @json.ctime then "past" else "future"
        err = new errors.ClockSkewError "your computer's clock is wrong: signature is dated #{diff} seconds in the #{epoch}"
        err.diff = diff
    cb err

  #---------------

  _check_version : ({v}, cb) ->
    err = if (x = @json.body.version) is v then null
    else new Error "Expected inner signature version #{v} but got #{errsan x}"
    cb err

  #---------------

  _check_expired : (cb) ->
    err = null
    now = @_get_now()
    if not @json.ctime? then err = new Error "No `ctime` in signature"
    else if not @json.expire_in? then err = new Error "No `expire_in` in signature"
    else if not @json.expire_in then @etime = null
    else if (expired = (now - @json.ctime - @json.expire_in)) > 0
      err = new Error "Expired #{expired}s ago"
    else
      @etime = @json.ctime + @json.expire_in
    cb err

  #---------------

  _sanity_check_high_skip : (cb) ->
    err = null
    {seqno, high_skip} = @json
    if high_skip.hash and not high_skip.seqno?
      err = new errors.BadHighSkipError "Cannot provide high_skip hash but not high_skip seqno."
    else if seqno is 1 and high_skip.seqno isnt 0
      err = new errors.BadHighSkipError "First seqno must provide high_skip seqno 0, if high_skip is provided."
    else if high_skip.seqno is 0 and high_skip.hash?
      err = new errors.BadHighSkipError "Cannot provide high_skip hash with high_skip seqno 0."
    else if high_skip.seqno > 0 and not high_skip.hash?
      err = new errors.BadHighSkipError "Must provide high_skip_hash with positive high_skip_seqno."
    else if high_skip.seqno < 0
      err = new errors.BadHighSkipError "high_skip seqno should be non-negative."
    cb err

  #---------------

  _parse_and_process : ({armored}, cb) ->
    err = null
    await @sig_eng.unbox armored, defer(err, payload, body), { @assert_pgp_hash }
    if not err? and not @skip_ids
      await @_check_ids body, defer err
    if not err? and @make_ids
      {@short_id, @id} = make_ids body
    cb err, payload

  #---------------

  _check_json : ({payload, expansions}, cb) ->
    esc = make_esc cb
    json_str_buf = payload

    # Before we run any checks on the input json, let's trim any leading
    # or trailing whitespace.
    json_str_utf8 = json_str_buf.toString('utf8')
    json_str_utf8_trimmed = trim json_str_utf8
    err = null
    if not /^[\x20-\x7e]+$/.test json_str_utf8_trimmed
      err = new Error "All JSON proof characters must be in the visible ASCII set (properly escaped UTF8 is permissible)"
      return cb err
    [e, json_tmp] = katch (() -> JSON.parse json_str_buf)
    if e?
      err = new Error "Couldn't parse JSON signed message: #{e.message}"
      return cb err
    if @strict and ((ours = trim(json_stringify_sorted(json_tmp))) isnt json_str_utf8_trimmed)
      err = new Error "non-canonical JSON found in strict mode (#{errsan ours} v #{errsan json_str_utf8_trimmed})"
      return cb err
    await akatch (() -> expand_json({ json : json_tmp, expansions})), esc defer @json
    await @base._v_check {@json, @assert_pgp_hash}, esc defer()
    cb null, @json, json_str_utf8

#==========================================================================

class Base

  #------

  constructor : ({@sig_eng, @seqno, @user, @host, @prev, @client, @merkle_root, @revoke, @seq_type, @ignore_if_unsupported, @high_skip, @eldest_kid, @expire_in, @ctime, @stub_paths}) ->

  #------

  proof_type_str : () ->
    if (t = @proof_type())? then proof_type_to_string[t]
    else null

  #------

  _v_check_key : (key) ->
    checks = 0
    if key?.kid?
      checks++
      err = @_v_check_kid key.kid
    if not err? and key?.fingerprint?
      checks++
      err = @_v_check_fingerprint key
    if not err?  and checks is 0
      err = new Error "need either a 'body.key.kid' or a 'body.key.fingerprint'"
    err

  #------

  _v_check_kid : (kid) ->
    if not bufeq_secure (a = @km().get_ekid()), (Buffer.from kid, "hex")
      err = new Error "Verification key doesn't match packet (via kid): #{errsan a.toString('hex')} != #{errsan kid}"
    else
      null

  #------

  _v_check_fingerprint : (key) ->
    if not (key_id = key?.key_id)?
      new Error "Needed a body.key.key_id but none given"
    else if not bufeq_secure (a = @km().get_pgp_key_id()), (Buffer.from key_id, "hex")
      new Error "Verification key doesn't match packet (via key ID): #{errsan a.toString('hex')} != #{errsan key_id}"
    else if not (fp = key?.fingerprint)?
      new Error "Needed a body.key.fingerprint but none given"
    else if not bufeq_secure @km().get_pgp_fingerprint(), (Buffer.from fp, "hex")
      new Error "Verifiation key doesn't match packet (via fingerprint)"
    else
      null

  #------

  # true if PGP details (full_hash and fingerprint) should be inserted at
  # @_v_pgp_details_dest()
  _v_include_pgp_details : -> false

  # true if this link type is only valid if it includes PGP details
  _v_require_pgp_details : -> false

  # Given the JSON body, the object where PGP key details should end up
  _v_pgp_details_dest : (body) -> body.key

  # If @_v_include_pgp_details() is true, a KeyManager containing a PGP key
  _v_pgp_km : () -> null

  # Most proofs require both username and UID but some may only require
  # one or the other.
  _v_require_username : () -> true
  _v_require_uid      : () -> true

  # Generates (and caches) a hash for PGP keys, returns null for other kinds of keys
  full_pgp_hash : (opts, cb) ->
    if @_full_pgp_hash is undefined
      esc = make_esc cb
      await @_v_pgp_km()?.pgp_full_hash {}, esc defer @_full_pgp_hash
    cb null, @_full_pgp_hash

  # Adds the PGP hash and fingerprint to `body`. Noop for non-PGP keys (unless
  # @_v_require_pgp_details returns true, then returns an error.)
  _add_pgp_details : ({body}, cb) ->
    return cb(null) unless @_v_include_pgp_details()

    dest = @_v_pgp_details_dest(body)
    await @full_pgp_hash {}, defer err, full_hash
    if err then # noop
    else if full_hash?
      dest.full_hash = full_hash
      dest.fingerprint = @_v_pgp_km().get_pgp_fingerprint().toString('hex') unless dest.fingerprint?
    else if @_v_require_pgp_details()
      err = new Error "#{@proof_type_str()} proofs require a PGP key"

    cb err

  _check_pgp_details: ({json}, cb) ->
    err = null
    details = @_v_pgp_details_dest(json.body)

    if not (hash_in = details?.full_hash)? or not (fp_in = details?.fingerprint)? or not (kid_in = details?.kid)?
      if @_v_require_pgp_details()
        err = new Error "#{@proof_type_str()} proofs require a PGP key's KID, fingerprint, and full_hash but one or more were missing."
    else
      await @full_pgp_hash {}, defer err, hash_real
      if err? then # noop
      else if not hash_real?
        err = new Error "A PGP key hash (#{hash_in}) was in the sig body but no key was provided"
      else if hash_in isnt hash_real
        err = new Error "New PGP key's hash (#{hash_real}) doesn't match hash in signature (#{hash_in})"
      else if fp_in isnt (fp_real = @_v_pgp_km().get_pgp_fingerprint().toString('hex'))
        err = new Error "New PGP key's fingerprint (#{fp_real}) doesn't match fingerprint in signature (#{fp_in})"
      else if kid_in isnt (kid_real = @_v_pgp_km().get_ekid().toString('hex'))
        err = new Error "New PGP key's KID (#{kid_real}) doesn't match KID in signature (#{kid_in})"

    cb err

  #------

  _v_check_user : ({json}) ->
    has_user_id = false

    if json?.body?.key?.username
      if not cieq (a = json?.body?.key?.username), (b = @user.local.username)
        return new Error "Wrong local user: got '#{errsan a}' but wanted '#{errsan b}'"
      else
        has_user_id = true
    else if @_v_require_username()
      return new Error "no username given, but was was required"

    if json?.body?.key?.uid
      if (a = json?.body?.key?.uid) isnt (b = @user.local.uid)
        return new Error "Wrong local uid: got '#{errsan a}' but wanted '#{errsan b}'"
      else
        has_user_id = true
    else if @_v_require_uid()
      return new Error "no uid given, but was was required"

    if (v = @user.local.emails)? and (e = json?.body?.key?.email)?
      if e.toLowerCase() in (x.toLowerCase() for x in v when x?)
        has_user_id = true
      else
        return new Error "given email '#{errsan e}' doesn't match"

    if not has_user_id
      return new Error "no UID or username given for signature"

    return null

  #------

  _v_check : ({json}, cb) ->
    # The default seq_type is PUBLIC
    seq_type = (v) -> if v? then v else constants.seq_types.PUBLIC

    err = @_v_check_user {json}

    err = if err? then err
    else if not cieq (a = json?.body?.key?.host), (b = @host)
      new Error "Wrong host: got '#{errsan a}' but wanted '#{errsan b}'"
    else if (a = @_type())? and ((b = json?.body?.type) isnt a)
      # Don't check if it's a "generic_binding", which doesn't much
      # care what the signature type is.  Imagine the case of just trying to
      # get the user's keybinding.  Then any signature will do.
      new Error "Wrong signature type; got '#{errsan a}' but wanted '#{errsan b}'"
    else if (a = @seqno) and (a isnt (b = json?.seqno))
      err = new errors.WrongSeqnoError "Wrong seqno; wanted '#{errsan a}' but got '#{errsan b}"
      err.seqno = b
      err
    else if (a = @prev) and (a isnt (b = json?.prev))
      new Error "Wrong previous hash; wanted '#{errsan a}' but got '#{errsan b}'"
    else if @seqno and (a = seq_type(json?.seq_type)) isnt (b = seq_type(@seq_type))
      new Error "Wrong seq_type: wanted '#{errsan b}' but got '#{errsan a}'"
    else if not (key = json?.body?.key)?
      new Error "no 'body.key' block in signature"
    # It's OK if server expects but high_skip clients don't send it, because
    # it is optional for now. If they both provide, must match.
    else if (a = json?.high_skip)? and (b = @high_skip)?
      if a.seqno isnt b.seqno
        new errors.BadHighSkipError "Wrong high_skip seqno: wanted '#{errsan b.seqno}' but got '#{errsan a.seqno}'"
      else if a.hash isnt b.hash
        new errors.BadHighSkipError "Wrong high_skip hash: wanted '#{errsan b.hash}' but got '#{errsan a.hash}'"
    else if (section_error = @_check_sections(json))?
      section_error
    else
      @_v_check_key key

    if not err?
      await @_check_pgp_details {json}, defer err

    cb err

  #------

  _required_sections : () -> ["key", "type", "version"]

  #------

  _optional_sections : () -> ["client", "merkle_root"]
  _is_wildcard_link : () -> false

  #------

  # Return a JavaScript Error on failure, or null if no failure.
  _check_sections : (json) ->
    for section in @_required_sections()
      unless json?.body?[section]
        return new Error "Missing '#{section}' section #{if json.seqno? then "in seqno " + json.seqno else ""}, required for #{errsan json.body.type} signatures"

    # Sometimes we don't really need to check, we just need a "key" section
    unless @_is_wildcard_link()
      for section, _ of json?.body
        unless (section in @_required_sections()) or (section in @_optional_sections())
          return new Error "'#{section}' section #{if json.seqno? then "in seqno " + json.seqno else ""} is not allowed for #{errsan json.body.type} signatures"

    null

  #------

  is_remote_proof : () -> false

  #------

  has_revoke : () -> has_revoke @


  #------

  _v_customize_json : (ret) ->
  _v_stub_paths : () -> null

  #------

  _do_stub_paths : ({json, expansions}, cb) ->
    esc = make_esc cb
    for path in (@stub_paths or @_v_stub_paths() or [])
      await akatch (() -> stub_json { path, json, expansions}), esc defer()
    cb null

  #------

  generate_json : ({expire_in, version} = {}, cb) ->
    err = null
    esc = make_esc cb

    version or= constants.versions.sig_v1

    # Cache the unix_time() we generate in case we need to call @generate_json()
    # twice.  This happens for reverse signatures!
    ctime = if @ctime? then @ctime else (@ctime = unix_time())

    pick = (v...) ->
      for e in v when e?
        return e
      return null

    ret = {
      seqno : @seqno
      prev : @prev
      ctime : ctime
      tag : constants.tags.sig
      expire_in : pick(expire_in, @expire_in, constants.expire_in)
      body :
        version : version
        type : @_type()
        key :
          host : @host
          username : @user.local.username
          uid : @user.local.uid
    }

    # Can't access ekids from GnuPG. We'd have to parse the keys (possible).
    if (ekid = @km().get_ekid())?
      ret.body.key.kid = ekid.toString('hex')

    if (fp = @km().get_pgp_fingerprint())?
      ret.body.key.fingerprint = fp.toString('hex')
      ret.body.key.key_id = @km().get_pgp_key_id().toString('hex')

    if @eldest_kid?
      ret.body.key.eldest_kid = @eldest_kid

    if (e = @user.local.email)?
      ret.body.key.email = e

    # Can be:
    #
    #   NONE : 0
    #   PUBLIC : 1  # this is the default!
    #   PRIVATE : 2
    #   SEMIPRIVATE : 3
    #
    ret.seq_type = @seq_type if @seq_type?

    ret.ignore_if_unsupported = !!@ignore_if_unsupported if @ignore_if_unsupported?

    ret.high_skip = @high_skip if @high_skip?

    ret.client = @client if @client?
    ret.body.merkle_root = @merkle_root if @merkle_root?
    ret.body.revoke = @revoke if @has_revoke()

    @_v_customize_json ret

    await @_add_pgp_details {body: ret.body}, esc defer()
    expansions = {}
    await @_do_stub_paths { json : ret, expansions }, esc defer()

    cb err, json_stringify_sorted(ret), ret, expansions

  #------

  _v_generate : (opts, cb) -> cb null

  #------

  generate : (cb) ->
    esc = make_esc cb, "generate"
    out = null
    opts = version : constants.versions.sig_v1
    await @_v_generate opts, esc defer()
    await @generate_json opts, esc defer json, json_obj, expansions
    inner = { str : json, obj : json_obj }
    await @sig_eng.box json, esc defer {pgp, raw, armored}
    {short_id, id} = make_ids raw
    out = { pgp, json, id, short_id, raw, armored, inner, expansions }
    cb null, out

  #------

  generate_v2 : (cb, {dohash} = {}) ->
    # If @seq_type isn't specified, then default to public
    @seq_type or= constants.seq_types.PUBLIC
    dohash or= false

    esc = make_esc cb, "generate"
    out = null
    opts = { version : constants.versions.sig_v2 }
    await @_v_generate opts, esc defer()
    await @generate_json opts, esc defer s, o, expansions
    inner = { str : s, obj : o }
    await @generate_outer { inner }, esc defer outer
    await @sig_eng.box outer, esc(defer({pgp, raw, armored})), { dohash }
    {short_id, id} = make_ids raw
    out = { pgp, id, short_id, raw, armored, inner, outer, expansions }
    cb null, out

  #------

  generate_versioned : ({version, dohash}, cb) ->
    switch version
      when constants.versions.sig_v2 then @generate_v2(cb, {dohash})
      else @generate(cb, {dohash})

  #------

  hex_to_buf : ({hex_str, n}, cb) ->
    err = buf = null

    if not hex_str?
      return cb null, buf
    # expect a SHA256 hash by default
    n or= 32
    try
      buf = Buffer.from(hex_str, 'hex')
    catch e
      err = new Error "failed to read #{errsan hex_str} as a hex string"
    if not err? and buf.length isnt n
      err = new Error "bad hash length: #{buf.length}"

    cb err, buf

  #------

  generate_outer : ({inner}, cb) ->
    esc = make_esc cb, "generate_outer"
    ret = prev_buf = unpacked = null

    await @hex_to_buf { hex_str: inner.obj?.prev }, esc defer prev_buf
    await @hex_to_buf { hex_str: inner.obj?.high_skip?.hash }, esc defer high_skip_hash_buf

    if inner.obj?.high_skip?
      high_skip = {
        seqno: inner.obj.high_skip.seqno,
        hash: high_skip_hash_buf
      }
    else
      high_skip = null

    unpacked = new OuterLink {
      version : constants.versions.sig_v2
      type : @_type_v2()
      seqno : (inner.obj.seqno or 0)
      prev : prev_buf
      hash : hash_sig(Buffer.from inner.str, 'utf8')
      seq_type : if (x = inner.obj.seq_type_for_testing)? then x else (inner.obj.seq_type or constants.seq_types.SEMIPRIVATE)
      ignore_if_unsupported : if (x = inner.obj.ignore_if_unsupported_for_testing)? then x else !!(inner.obj.ignore_if_unsupported or false)
      high_skip : high_skip
    }
    ret = unpacked.pack()

    cb null, ret, unpacked

  #------

  # @param {Object} obj with options as specified:
  # @option obj {string} pgp The PGP signature that's being uploaded
  # @option obj {string} armored The signature that's being uploaded (either PGP or KB NaCl)
  # @option obj {string} id The keybase-appropriate ID that's the PGP signature's hash
  # @option obj {string} short_id The shortened sig ID that's for the tweet (or similar)
  # @option obj {bool} skip_ids Don't bother checking IDs
  # @option obj {bool} make_ids Make Ids when verifying
  # @option obj {bool} strict Turn on all strict-mode checks
  # @option obj {Function} assert_pgp_hash Callback to reject specific PGP hash functions if encountered
  verify : (obj, cb) ->
    verifier = new Verifier obj, @sig_eng, @
    await verifier.verify defer err, json_obj, json_str
    id = short_id = null
    if obj.make_ids
      id = obj.id = verifier.id
      short_id = obj.short_id = verifier.short_id
    out = if err? then {}
    else {json_obj, json_str, id, short_id, etime : verifier.get_etime(), @reverse_sig_kid, @reverse_sig, version : constants.versions.sig_v1 }
    cb err, out

  #-------

  # @param {Object} obj with options as specified:
  # @option obj {string} armored The signature that's being uploaded (either PGP or KB NaCl)
  # @option obj {string} inner The inner payload
  # @option obj {string} id The keybase-appropriate ID that's the PGP signature's hash
  # @option obj {string} short_id The shortened sig ID that's for the tweet (or similar)
  # @option obj {string} expansions Dictionary of hash -> object expansions
  # @option obj {bool} skip_ids Don't bother checking IDs
  # @option obj {bool} make_ids Make Ids when verifying
  # @option obj {bool} strict Turn on all strict-mode checks
  verify_v2 : (obj, cb) ->
    verifier = new Verifier obj, @sig_eng, @
    await verifier.verify_v2 defer err, outer, json_obj, json_str
    id = short_id = null
    if obj.make_ids
      id = obj.id = verifier.id
      short_id = obj.short_id = verifier.short_id
    out = if err? then {}
    else {json_obj, json_str, id, short_id, etime : verifier.get_etime(), @reverse_sig_kid, @reverse_sig, outer, version : constants.versions.sig_v2 }
    cb err, out

  #-------

  # @param {Object} obj with options as in verify and verify_v2. If obj.inner?
  #  is specified separately, then assume v2.
  verify_all_versions : (obj, cb) ->
    if obj.inner? then @verify_v2 obj, cb
    else @verify obj, cb

  #-------

  km : () -> @sig_eng.get_km()

  #-------

  check_inputs : () -> null

  #-------

  # Check this proof against the existing proofs
  check_existing : () -> null

  #-------

  # Some proofs are shortened, like Twitter, due to the space-constraints on the medium.
  is_short : () -> false

  #-------

  # Check the server's work when we ask for it to generate a proof text.
  # Make sure our sig shows up in there but no one else's.  This will
  # vary between long and short signatures.
  sanity_check_proof_text : ({ args, proof_text}, cb) ->
    if @is_short()
      check_for = args.sig_id_short
      len_floor = constants.short_id_bytes
      slack = 3
    else
      [ err, msg ] = kbpgp.ukm.decode_sig { armored: args.sig }
      if not err? and (msg.type isnt kbpgp.const.openpgp.message_types.generic)
        err = new Error "wrong message type; expected a generic message; got #{errsan msg.type}"
      if not err?
        check_for = msg.body.toString('base64')
        len_floor = constants.shortest_pgp_signature
        slack = 30 # 30 bytes of prefix/suffix data available
    unless err?
      b64s = base64_extract proof_text
      for b in b64s when (b.length >= len_floor)
        if b.indexOf(check_for) < 0 or (s = (b.length - check_for.length)) > slack
          err = new Error "Found a bad signature in proof text: #{b[0...60]} != #{check_for[0...60]} (slack=#{s})"
          break
    cb err

#==========================================================================

class OuterLink

  # Fields after `type` were added later. Fields must be filled in order. Valid combinations:
  # - first 5 filled
  # - first 6 filled
  # - first 7 filled
  # - first 9 filled
  # It is invalid to fill ignore_if_unsupported by not seq_type.
  constructor : ({@version, @seqno, @prev, @hash, @type, @seq_type, @ignore_if_unsupported, @high_skip}) ->

  @parse : ({raw}, cb) ->
    esc = make_esc cb, "OuterLink.parse"
    await akatch (() -> purepack.unpack raw), esc defer arr
    err = ret = null
    if arr.length not in [5, 6, 7, 9]
      err = new Error "expected 5, 6, 7, or 9 fields; got #{arr.length}"
    else
      arg = {
        version : arr[0],
        seqno : arr[1],
        prev : arr[2],
        hash : arr[3],
        type : arr[4],
        seq_type : arr[5],
        ignore_if_unsupported : arr[6],
      }
      # If reading a 2.3-or-later link, fill in the info, for either a high or
      # a low link. Otherwise, don't set high_skip for older clients.
      if arr.length >= 9
        arg.high_skip = {
          seqno : arr[7],
          hash : arr[8]
        }
      ret = new OuterLink arg
    cb err, ret

  get_seq_type : () -> if @seq_type then @seq_type else constants.seq_types.SEMIPRIVATE

  get_ignore_if_unsupported : () -> if @ignore_if_unsupported then @ignore_if_unsupported else false

  get_high_skip : () -> @high_skip or null

  pack : () ->
    # For backwards-compatibility, if the incoming chainlink doesn't have a
    # values for seq_type and ignore_if_unsupported then we don't push null or
    # default values, we just leave it as a 5-value array.
    # If it has seq_type but not ignore_if_unsupported, then we leave a 6-value array.
    # It is invalid but not detected here to have a ignore_if_unsupported value but not seq_type.
    arr = [ @version, @seqno, @prev, @hash, @type ]

    # For newer clients that push an explicit seq_type value, we push it onto the array here
    arr.push @seq_type if @seq_type?

    arr.push (!!@ignore_if_unsupported) if @ignore_if_unsupported?

    # If an older client wants to make an outer link, they will get null in both fields.
    # If a newer client wants to make a first link, they should send high_skip_seqno=0,
    # a seqno which is never actually used, and leave high_skip_hash as null.
    if @high_skip?
      arr.push @high_skip.seqno
      arr.push @high_skip.hash

    purepack.pack arr

  outer_link_hash : () -> hash_sig(@pack())

#==========================================================================

class GenericBinding extends Base
  _type : () -> null
  resource_id : () -> ""
  _service_obj_check : () -> true
  _is_wildcard_link : () -> true

#==========================================================================

exports.Base = Base
exports.GenericBinding = GenericBinding
exports.OuterLink = OuterLink
exports.sig_id_to_short_id = sig_id_to_short_id
exports.sig_id_to_med_id = sig_id_to_med_id
exports.make_ids = make_ids
exports.add_ids = add_ids
exports.proof_text_check_to_med_id = proof_text_check_to_med_id

#==========================================================================
