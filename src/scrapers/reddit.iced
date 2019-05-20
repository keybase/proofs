{sncmp,BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{proof_text_check_to_med_id} = require '../base'

#================================================================================

PREFIX = "https://www.reddit.com"
SUBREDDIT = PREFIX + "/r/keybaseproofs"

#================================================================================

exports.RedditScraper = class RedditScraper extends BaseScraper

  constructor: (opts) ->
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not(args.username?)
      new Error "Bad args to Reddit proof: no username given"
    else if not (args.name?) or (args.name isnt 'reddit')
      new Error "Bad args to Reddit proof: type is #{args.name}"
    else
      null


  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    rxx = new RegExp("^#{SUBREDDIT}", "i")
    return (api_url? and api_url.match(rxx));

  # ---------------------------------------------------------------------------

  hunt2 : ({username, proof_text_check, name}, cb) ->
    if (err = @_check_args { username, name })?
      return cb err, { rc: v_codes.BAD_ARGS }

    await @_get_url_body
      url: "#{PREFIX}/user/#{encodeURIComponent(username)}/submitted.json?count=25&cachebust=#{Math.random()}"
      json: true
    , defer err, rc, json

    if err? or rc isnt v_codes.OK
      return cb err, rc: rc

    if not (posts = @unpack_posts json)?
      return cb (new Error "Couldn't get Reddit user #{username}'s posts: #{json.error}"),
        rc: v_codes.FAILED_PARSE

    proof_post = null

    @log "+ Reddit user #{username}'s posts:"

    for post in posts
      @log "| title: #{post.title}"
      if (rc = @check_post { post, username, proof_text_check }) is v_codes.OK
        @log "| Found a good post!"
        proof_post = post
        break
      else
        @log "| hunt failed with rc=#{rc}"

    @log "- Scan of posts with OK=#{proof_post?}"

    if not proof_post?
      return cb null, rc: v_codes.NOT_FOUND

    cb null,
      rc : v_codes.OK
      api_url : PREFIX + proof_post.permalink + ".json"
      human_url : PREFIX + proof_post.permalink
      remote_id : proof_post.name

  # ---------------------------------------------------------------------------

  unpack_posts : (json) ->
    if (json?.kind is 'Listing') and (posts = json?.data?.children)? and (posts.length is 0 or posts[0].kind is 't3')
      (data for {data} in posts)
    else
      null

  # ---------------------------------------------------------------------------

  unpack_post : (json) ->
    if (json[0]?.kind is 'Listing') and ((parent = json[0]?.data?.children?[0])?.kind is 't3')
      parent.data
    else
      null

  # ---------------------------------------------------------------------------

  check_post : ({post, username, proof_text_check}) ->
    med_id = proof_text_check_to_med_id proof_text_check
    if not (post?.subreddit? and post.author? and post.selftext? and post.title?)
      v_codes.CONTENT_MISSING
    else if (post.subreddit.toLowerCase() isnt 'keybaseproofs')
      v_codes.SERVICE_ERROR
    else if not sncmp(post.author, username)
      v_codes.BAD_USERNAME
    else if (post.title.indexOf(med_id) < 0)
      v_codes.TITLE_NOT_FOUND
    else
      if @_find_sig_in_raw(proof_text_check, post.selftext) then v_codes.OK
      else v_codes.TEXT_NOT_FOUND

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->

    # calls back with a v_code or null if it was ok
    await @_get_url_body {
      url : api_url + "?cachebust=#{Math.random()}"
      json : true
      user_agent : "linux:com.github/keybase/proofs:v2.1.41 (by /u/maxtaco)"
    }, defer err, rc, json

    rc = if rc isnt v_codes.OK then rc
    else if not (post = @unpack_post json)? then v_codes.CONTENT_FAILURE
    else @check_post { post, username, proof_text_check }
    cb err, rc

#================================================================================

