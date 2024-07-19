{sncmp,BaseScraper,BaseBearerToken} = require './base'
{TwitterScraper} = require './twitter'
{make_ids} = require '../base'
{constants} = require '../constants'
{v_codes} = constants
{decode_sig} = require('kbpgp').ukm
{Lock} = require '../util'
urlmod = require 'url'
schema = require '../schema3'

#================================================================================

ws_normalize = (x) ->
  v = x.split(/[\t\r\n ]+/)
  v.shift() if v.length and v[0].length is 0
  v.pop() if v.length and v[-1...][0].length is 0
  v.join ' '

#================================================================================

exports.TwitterBatchScraper = class TwitterBatchScraper extends TwitterScraper
  constructor: (opts) ->
    @_tweet_cache = opts.tweet_cache
    @cache_refresh_interval = opts.cache_refresh_interval
    super opts

  _hunt_batch : (cb) ->
    query =
      query : "\"Verifying myself\" \"Keybase.io\""
      expansions: "author_screen_name"
      "user.fields": "url,username"
      "tweet.fields": "created_at"
      max_results: 60
    if since_id = @_tweet_cache.last_id
      # Do not fetch tweets that were already cached.
      query.since_id = since_id

    u = urlmod.format {
      host : "api.twitter.com"
      protocol : "https:"
      pathname : "/2/tweets/search/recent"
      query
    }

    await @_get_body_api { url : u }, defer err, rc, json
    @log "| search index #{u} -> #{rc}"
    if rc isnt v_codes.OK then #noop
    else if not json? or (json.length is 0) then rc = v_codes.EMPTY_JSON
    else if not json.data? then rc = v_codes.INVALID_JSON
    else
      console.log json.data
      for {id, created_at, username, text}, i in json.data
        created_at = new Date(created_at)
        unless isFinite(created_at)
          @log "got invalid date in tweet JSON id: #{id}, created_at: #{tweet.created_at}"
          continue
        @log "ingesting tweet: id: #{id}, username: #{username}, text: \"#{text}\""
        @_tweet_cache.inform { id, created_at, username, text }

    cb null, v_codes.OK

  hunt2 : ({username, name, proof_text_check}, cb) ->
    # See if we should refresh cache.
    await @_tweet_cache.lock.acquire defer()
    err = null
    now = Math.floor(Date.now() / 1000)
    if now - @_tweet_cache.fetched_at > @cache_refresh_interval
      @_tweet_cache.fetched_at = now
      await @_hunt_batch defer err, rc
      if not err and rc isnt v_codes.OK
        err = new Error("rc: #{rc}")
    @_tweet_cache.lock.release()
    if err
      @logl "error", "error when hunting batch: #{err.toString()}"
      return cb err

    out = {}
    rc = v_codes.NOT_FOUND
    current_tweet = @_tweet_cache.tweets.get(username)
    if current_tweet and (@find_sig_in_tweet { inside : current_tweet.text, proof_text_check }) is v_codes.OK
      rc = v_codes.OK
      remote_id = current_tweet.id
      api_url = human_url = @_id_to_url username, remote_id
      out = { remote_id, api_url, human_url }
    out.rc = rc
    cb err, out

#================================================================================

exports.TweetCache = class TweetCache
  constructor : () ->
    @tweets = new Map() # username -> tweet
    @last_id = null
    @fetched_at = 0
    @lock = new Lock()

  inform : ({id, created_at, username, text}) ->
    current = @tweets.get(username)
    if current and current.created_at >= created_at
      # We already have this tweet or more recent tweet for this user.
      return
    @tweets.set(username, { id, created_at, text })
