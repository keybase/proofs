{sncmp,BaseScraper,BaseBearerToken} = require './base'
{make_ids} = require '../base'
{constants} = require '../constants'
{v_codes} = constants
{decode_sig} = require('kbpgp').ukm
urlmod = require 'url'
schema = require '../schema3'

#================================================================================

ws_normalize = (x) ->
  v = x.split(/[\t\r\n ]+/)
  v.shift() if v.length and v[0].length is 0
  v.pop() if v.length and v[-1...][0].length is 0
  v.join ' '

#================================================================================

class TwitterBearerToken extends BaseBearerToken
  constructor : ({@base}) ->
    super {
      name: "Twitter"
      @base
      access_token_url : "https://api.twitter.com/oauth2/token"
      scope : [ 'history', 'read' ]
    }

#================================================================================

_bearer_token = null
bearer_token = ({base}) ->
  unless _bearer_token
    _bearer_token = new TwitterBearerToken { base }
  return _bearer_token

#================================================================================

exports.TwitterScraper = class TwitterScraper extends BaseScraper
  username_regexp = /^[a-z0-9_-]{2,15}$/

  constructor: (opts) ->
    @auth = opts.auth
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not(args.username?)
      new Error "Bad args to Twitter proof: no username given"
    else if not (args.name?) or (args.name isnt 'twitter')
      new Error "Bad args to Twitter proof: type is #{args.name}"
    else if not args.username.match(username_regexp)
      new Error "Invalid username passed to Twitter proof"
    else
      null

  # ---------------------------------------------------------------------------

  hunt2 : ({username, name, proof_text_check}, cb) ->
    # calls back with err, out
    out      = {}
    rc       = v_codes.OK

    return cb(err,out) if (err = @_check_args { username, name })?

    endpoint_name = "/2/tweets/search/recent"
    u = urlmod.format {
      host : "api.twitter.com"
      protocol : "https:"
      pathname : endpoint_name
      query :
        query : "\"Verifying myself\" \"Keybase.io\" from:#{username}"
    }
    await @_get_body_api { url : u, endpoint_name }, defer err, rc, json
    @log "| search index #{u} -> #{rc}"
    if rc isnt v_codes.OK then #noop
    else if not json? or (json.length is 0) then rc = v_codes.EMPTY_JSON
    else if not json.data?
      if json.meta?.result_count is 0
        # No results.
        rc = v_codes.NOT_FOUND
      else
        # Unknown JSON structure.
        rc = v_codes.INVALID_JSON
    else
      rc = v_codes.NOT_FOUND
      for {text, id},i in json.data
        if (@find_sig_in_tweet { inside : text, proof_text_check }) is v_codes.OK
          @log "| found valid tweet in stream @ #{i}"
          rc = v_codes.OK
          remote_id = id
          api_url = human_url = @_id_to_url username, remote_id
          out = { remote_id, api_url, human_url }
          break
    out.rc = rc
    cb err, out

  # ---------------------------------------------------------------------------

  users_lookup: ({ids, screen_names, cursor_wait, include_entities}, cb) ->
    # accepts ids or screen_names (not both), and returns
    # with an array in the same order
    #
    # calls back with err, user_infos given some numerical twitter ids
    # includes null results for any missing users, so the output array matches
    # input
    if ids and screen_names then throw new Error 'users_lookup cannot take ids and screen_names'
    input_list        = ids or screen_names
    err               = null
    responses         = []
    cursor_wait       = if cursor_wait? then cursor_wait else 100 # ms
    i                 = 0
    include_entities  = if include_entities? then include_entities else false
    batch_size        = 100 # it's the twitter maximum
    done              = false

    while not done
      j = Math.min(i+batch_size, input_list.length)
      query = {include_entities}
      if ids?
        query.user_id = ids[i...j].join ','
      else
        query.screen_name = screen_names[i...j].join ','
      u = urlmod.format {
        host:       "api.twitter.com"
        protocol:   "https:"
        pathname:   "/1.1/users/lookup.json"
        query:      query
      }
      await @_get_body_api {url: u}, defer err, rc, json
      @log "| users_lookup #{i}...#{j}"
      if err?
        done = true
      else if rc isnt v_codes.OK
        err  = new Error("failed to scrape; not ok #{rc}")
        done = true
      else if not json?.length
        err = new Error("failed to scrape; empty json #{v_codes.EMPTY_JSON}")
        done = true
      else
        responses.push u for u in json
        if j isnt input_list.length
          i = j
          await setTimeout defer(), cursor_wait
        else
          done = true
        @log "| got #{json.length} more; total=#{responses.length}"

    # twitter may not obey our matching request order
    if responses?.length
      dict = {}
      key  = if ids? then "id_str" else "screen_name"
      dict[r[key]] = r for r in responses
      res = []
      for identifier, i in input_list
        res[i] = dict[identifier] or null

    cb err, res

  # ---------------------------------------------------------------------------

  get_follower_ids: ({username, cursor_wait, stop_at, friends}, cb) ->
    # if friends is true, then looks up people they follow instead
    # calls back with err, twitter_id_list
    done        = false
    cursor      = -1
    err         = null
    res         = []
    cursor_wait = if cursor_wait? then cursor_wait else 1000 # ms
    stop_at     = stop_at or Infinity
    while not done
      u = urlmod.format {
        host:       "api.twitter.com"
        protocol:   "https:"
        pathname:   "/1.1/#{if friends then 'friends' else 'followers'}/ids.json"
        query:
          stringify_ids: true
          cursor:        cursor
          screen_name:   username
          count:         5000 # max
      }
      await @_get_body_api {url: u}, defer err, rc, json
      @log "| get_followers #{username} (#{cursor})"
      if err?
        done = true
      else if rc isnt v_codes.OK
        err  = new Error("got bad code from get_body_api #{rc}")
        err.code = rc
        done = true
      else if not json?.ids?
        err  = new Error("got empty_json from get_body_api")
        err.code = v_codes.EMPTY_JSON
        done = true
      else
        res.push x for x in json.ids
        if json.next_cursor and (res.length < stop_at)
          cursor = json.next_cursor_str
          await setTimeout defer(), cursor_wait
        else
          done = true
        @log "| got #{json.ids.length} more; total=#{res.length}"

    cb err, res

  # ---------------------------------------------------------------------------

  _id_to_url : (username, status_id) ->
    "https://twitter.com/#{username}/status/#{status_id}"

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    return (api_url.indexOf("https://twitter.com/#{username}/") is 0)

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the proof_text_check matches the sig.
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode_sig { armored: signature }
    if not err?
      {short_id} = make_ids msg.body
      if proof_text_check.indexOf(" " + short_id + " ")  < 0
        err = new Error "Cannot find #{short_id} in #{proof_text_check}"
    return err

  # ---------------------------------------------------------------------------

  find_sig_in_tweet : ({inside, tweet_p, proof_text_check}) ->

    if tweet_p? and not inside?
      inside = tweet_p.text()
      html = tweet_p.html()
    else
      html = null

    # MK 2014/06/24
    # Map 1+ spaces to 1 space in both cases.  Also pop and shift off any leading
    # and trailing spaces.
    inside = ws_normalize inside
    proof_text_check = ws_normalize proof_text_check

    # Oh boy what's going on here? Twitter changed their tweet formatting
    # sometime in January 2018, so where old tweets have just "Keybase.io"
    # text, new tweets make it a link. We need to expect both. Also the hunter
    # and the scraper see two slightly different things, so we actually need to
    # handle 3 cases.
    rxx_text = proof_text_check.replace(" on Keybase.io.", " on (Keybase.io|https://t\\.co/\\S*|http://Keybase\\.io\\s)\\.")
    rxx = new RegExp ("^" + rxx_text + ".*")

    @log "+ Checking tweet '#{inside}' for signature '#{rxx}'"
    @log "| Incoming check text: #{proof_text_check}"
    @log "| html is: #{html.replace( /\n/g, ' ').trim()}" if html?

    x = /^(@[a-zA-Z0-9_-]+\s+)/
    while (m = inside.match(x))?
      p = m[1]
      inside = inside[p.length...]
      @log "| Stripping off @prefix: #{p}"
    rc = if inside.match(rxx)? then v_codes.OK else v_codes.DELETED
    @log "- Result -> #{rc}"
    return rc

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->

    if not api_url?.length
      rc = v_codes.FAILED_PARSE
      err = new Error "null api_url API for #{remote_id}/#{username}"
      @log "null api_url for #{remote_id}/#{username}"
      return cb err, rc

    # Do not try to fetch api_url which is of form:
    # "https://twitter.com/tacovontaco/status/673931888088625152"
    # because Twitter serves a JavaScript-based page there and the contents of
    # tweet are not available. Instead, construct a new url to oembed API with
    # the tweet ID. That API doesn't require authentication and claims not to
    # be rate limited:
    # https://developer.twitter.com/en/docs/twitter-api/v1/tweets/post-and-engage/api-reference/get-statuses-oembed
    u = new urlmod.URL('https://api.twitter.com/1/statuses/oembed.json')
    u.searchParams.set('id', remote_id.toString())
    # tell twitter not to include their <script> tag in result.
    u.searchParams.set('omit_script', '1')

    new_api_url = urlmod.format u
    @log "| use oembed API #{new_api_url} for tweet at #{api_url} (remote_id=#{remote_id})"

    # calls back with a v_code or null if it was ok
    await @_get_url_body { url : new_api_url, json : true }, defer err, rc, body_obj

    if not err and rc is v_codes.OK
      schm = schema.dict({
        url: schema.string().name('url')
        author_url: schema.string().name('author_url')
        html: schema.string().name('html')
      }).allow_extra_keys()
      if err = schm.check body_obj
        return cb err, v_codes.CONTENT_FAILURE

      # "url" field returned by the API should match api_url.
      if not(sncmp(body_obj.url, api_url))
        err = new Error "returned url field doesn't match api_url (found: #{body_obj.url}, expected: #{api_url})"
        return cb err, v_codes.CONTENT_FAILURE

      # Extract username from URL, do not use "author_name" because it's the
      # full name.
      api_url_matches = api_url.match(new RegExp("^https://twitter\\.com/([^/]+)/status/(\\d+)(.*)$"))
      if not api_url_matches
        err = new Error "api_url field doesn't match regexp, got: #{api_url_matches}"
        return cb err, v_codes.CONTENT_FAILURE

      # Check username and tweet ID.
      [_, username_from_url, tweet_id] = api_url_matches
      if not(sncmp(username, username_from_url))
        err = new Error("username from api_url didn't match, expected: #{username}, got: #{username_from_url}")
        return cb err, v_codes.BAD_USERNAME
      if tweet_id isnt remote_id.toString()
        return cb err, v_codes.BAD_REMOTE_ID

      # Check "author_url" field, it contains a link to user's twitter profile.
      # It should match our username.
      author_url_matches = body_obj.author_url.match(new RegExp("^https://twitter\\.com/(.+)$"))
      if not author_url_matches
        err = new Error("author_url doesn't match regexp, got: #{body_obj.author_url}")
        return cb err, v_codes.CONTENT_FAILURE

      [_, author_username] = author_url_matches
      if not(sncmp(username, author_username))
        err = new Error("username from author_url didn't match, expected: #{username}, got: #{author_username}")
        return cb err, v_codes.BAD_USERNAME

      if body_obj.html.length > 1000
        err = new Error("html is #{body_obj.html.length} characters, not trying to parse it")
        return cb err, v_codes.CONTENT_FAILURE

      $ = @libs.cheerio.load body_obj.html
      tweet_p = $('blockquote.twitter-tweet p')
      if tweet_p.length isnt 1
        err = new Error("failed to find tweet <p> in returned 'html' field")
        return cb err, v_codes.FAILED_PARSE

      rc = @find_sig_in_tweet { tweet_p, proof_text_check }

    cb err, rc

  # ---------------------------------------------------------------------------

  _get_bearer_token : (cb) ->
    bt = bearer_token { base : @ }
    await bt.get defer err, tok
    rc = if err? then v_codes.AUTH_FAILED else v_codes.OK
    cb err, rc, tok

  # ---------------------------------------------------------------------------

  # Only the hunter needs this
  _get_body_api : ({url, endpoint_name}, cb) ->
    rc = body = err = null
    await @_get_bearer_token defer err, rc, tok
    unless err?
      @log "| HTTP API request for URL '#{url}'"
      args =
        url : url
        headers :
          Authorization : "Bearer #{tok}"
        method : "get"
        json : true
        log_ratelimit : endpoint_name?
        endpoint_name : endpoint_name
      await @_get_url_body args, defer err, rc, body
    cb err, rc, body

#================================================================================
