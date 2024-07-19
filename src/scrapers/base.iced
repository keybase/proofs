{constants} = require '../constants'
{v_codes} = constants
pkg = require '../../package.json'
{decode_sig} = require('kbpgp').ukm
{space_normalize} = require '../util'
{b64find} = require '../b64extract'
urlmod = require 'url'
{callbackify} = require 'util'
{Lock} = require '../util'

#==============================================================

exports.user_agent = user_agent = constants.user_agent + pkg.version

#==============================================================

class BaseScraper
  constructor : ({@libs, log_level, @proxy, @ca}) ->
    @log_level = log_level or "debug"

  hunt : (username, proof_check_text, cb) -> hunt2 { username, proof_check_text }, cb
  hunt2 : (args, cb) -> cb new Error "unimplemented"
  id_to_url : (username, status_id) ->
  check_status : ({username, url, signature, status_id}, cb) -> cb new Error("check_status not implemented"), v_codes.NOT_FOUND
  _check_args : () -> new Error "unimplemented"
  _check_api_url : () -> false # unimplemented

  #-------------------------------------------------------------

  # Can we trust it over Tor? HTTP and DNS aren't trustworthy over
  # Tor, but HTTPS is.
  get_tor_error : (args) -> [ null, v_codes.OK ]

  #-------------------------------------------------------------

  logl : (level, msg) ->
    if (k = @libs.log)? then k[level](msg)

  #-------------------------------------------------------------

  log : (msg) ->
    if (k = @libs.log)? and @log_level? then k[@log_level](msg)

  #-------------------------------------------------------------

  validate : (args, cb) ->
    err = null
    rc = null
    if (err = @_check_args(args)) then # noop
    else if not @_check_api_url args
      err = new Error "check url failed for #{JSON.stringify args}"
    else
      err = @_validate_text_check args
    unless err?
      await @check_status args, defer err, rc
    cb err, rc

  #-------------------------------------------------------------

  # Given a validated signature, check that the payload_text_check matches the sig.
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode_sig { armored: signature }
    # PGP sigs need some newline massaging here, but NaCl sigs don't.
    if not err? and ("\n\n" + msg.payload + "\n") isnt proof_text_check and msg.payload isnt proof_text_check
      err = new Error "Bad payload text_check"
    return err

  #-------------------------------------------------------------

  # Convert away from MS-dos style encoding...
  _stripr : (m) ->
    m.split('\r').join('')

  #-------------------------------------------------------------

  _find_sig_in_raw : (proof_text_check, raw) ->
    ptc_buf = Buffer.from proof_text_check, "base64"
    return b64find raw, ptc_buf

  #-------------------------------------------------------------

  _get_rate_limit_header : (headers, name) ->
    # Twitter and Github can't agree on rate limit header names.
    if ((v = parse_int_or_undefined headers.get("X-RateLimit-#{name}")) or
        (v = parse_int_or_undefined headers.get("X-Rate-Limit-#{name}")))
      return v
    else
      return undefined

  _get_url_body: (opts, cb) ->
    ###
      cb(err, status, body) only replies with body if status is 200
    ###
    opts.timeout ?= constants.http_timeout
    opts.headers or= {}
    opts.headers["User-Agent"] ?= (opts.user_agent or user_agent)
    await @libs.fetch opts.url, opts, defer(err, response)
    if opts.log_ratelimit and response?
      rl_limit     = @_get_rate_limit_header response.headers, 'Limit' # 5000 for github # https://developer.github.com/v3/#rate-limiting
      rl_remaining = @_get_rate_limit_header response.headers, 'Remaining'
      rl_reset     = @_get_rate_limit_header response.headers, 'Reset' # utc timestamp in seconds when limit will replenish
      if rl_limit?
        @log "| ratelimit info limit=#{rl_limit} remaining=#{rl_remaining} reset=#{rl_reset}"
      @libs.ratelimit_inform? {
        limit: rl_limit
        remaining: rl_remaining
        reset: rl_reset
        endpoint_name : opts.endpoint_name
      }
    rc = if err?
      if err.message.includes('network timeout') then v_codes.TIMEOUT
      else                                            v_codes.HOST_UNREACHABLE
    else if (response.status in [401,403]) then v_codes.PERMISSION_DENIED
    else if (response.status is 200)       then v_codes.OK
    else if (response.status >= 500)       then v_codes.HTTP_500
    else if (response.status >= 400)       then v_codes.HTTP_400
    else if (response.status >= 300)       then v_codes.HTTP_300
    else                                        v_codes.HTTP_OTHER
    if rc is v_codes.OK
      try
        if opts.json
          f = callbackify response.json
          await f.call response, defer err, body
          if err
            @log "| _get_url_body response.json() failed with: #{err.toString()}"
            rc = v_codes.CONTENT_FAILURE
          cb err, rc, body
        else
          response.text().then (body) ->
            cb err, rc, body
      catch err
        cb err, rc, null
    else
      # TODO: It's possible to get response body here, which might be useful
      # for debugging and logging.
      cb err, rc, null

  #--------------------------------------------------------------

#==============================================================

exports.BaseScraper = BaseScraper

#==============================================================

exports.BaseBearerToken = class BaseBearerToken
  constructor : ({@name, @base, @access_token_url, @scope, @user_agent}) ->
    unless @access_token_url?
      throw new Error "@access_token_url is required"
    if @scope? and not Array.isArray(@scope)
      throw new Error "@scope has to be an array if present"

    @_tok = null
    @_created = 0
    @_lock = new Lock()
    @auth = @base.auth

  #----------------

  get : (cb) ->
    await @_lock.acquire defer()
    err = null
    now = Math.floor(Date.now() / 1000)

    if not (res = @_tok)? or (now - @_created > @auth.lifespan)

      @base.log "+ Request for bearer token"

      # Very crypto!  Not sure why this is done, but it's done
      cred = (Buffer.from [ @auth.key, @auth.secret ].join(":")).toString('base64')

      req = 'grant_type=client_credentials'
      if @scope
        req += "&scope=#{encodeURIComponent(@scope.join(' '))}"

      opts =
        url : @access_token_url
        headers :
          Authorization : "Basic #{cred}"
          'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          'Content-Length': req.length
        method : "post"
        body : req
      if @user_agent
        opts.user_agent = @user_agent
      await @base._get_url_body opts, defer err, rc, body

      if err?
        @base.logl 'error', "In getting bearer_token: #{err.message}"
      else if (rc isnt v_codes.OK)
        @base.logl 'error', "error in getting bearer token: #{rc}"
        err = new Error "error: #{rc}"
      else
        try
          body = JSON.parse body
        catch e
          @base.logl 'warn', "Could not parse JSON reply: #{e}"
          err = e

      if err? then # noop
      else if not (tok = body.access_token)?
        @base.logl 'warn', "No access token found in reply"
        err = new Error "#{@name} error: no access token"
      else
        @_tok = tok
        @_created = Math.floor(Date.now() / 1000)
        res = @_tok

      @base.log "- Request for bearer token for #{@name} -> err: #{err}"
      unless err
        @base.log "Bearer token for #{@name} is: #{res?.substr(0,5)}..."

    @_lock.release()
    cb err, res

#==============================================================

parse_int_or_undefined = (value) ->
  if (out = Number(value)) is parseInt(value) and !isNaN(out)
    return out

#==============================================================

exports.sncmp = sncmp = (a,b) ->
  if not a? or not b? then false
  else
    a = ("" + a).toLowerCase()
    b = ("" + b).toLowerCase()
    (a is b)

#================================================================================
