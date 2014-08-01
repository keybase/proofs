{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{decode} = require('pgp-utils').armor
{Lock} = require 'iced-lock'
{make_esc} = require 'iced-error'

#================================================================================

PREFIX = "https://www.reddit.com"
SUBREDDIT = PREFIX + "/r/keybaseproofs"

#================================================================================

class GlobalHunter

  constructor : () ->
    @_startup_window = 20*60 # on startup, go back 20 minutes
    @_delay = 5000 # always wait 5s = 5000msec
    @_running = false
    @_lock = new Lock
    @_cache = {}
    @_list = []
    @_last_rc = null

  #---------------------------

  index : (lst) ->
    for el in lst
      data = el.data
      author = data.author.toLowerCase()
      existing = @_cache[author]
      if not existing? or existing.data.name isnt data.name
        @_scraper.log "| Indexing #{author}: #{data.name} / #{data.permalink} @ #{data.created_utc}"
      @_cache[author] = el

  #---------------------------

  go_back : (stop, cb) ->
    after = null
    go = true
    esc = make_esc cb, "go_back"
    lst = []
    while go
      args =
        url : SUBREDDIT + "/.json"
        json : true
        qs: 
          count : 25
      args.qs.after = after if after?
      await @_scraper._get_url_body args, defer err, @_last_rc, body
      after = body.data.after
      lst = lst.concat body.data.children
      go = false if not after? or body.data.children[-1...][0].created_utc < stop
    lst.reverse()
    @_list = @_list.concat lst
    @index @_list
    cb null

  #---------------------------

  scrape : (cb) ->
    stop = if @_list.length then @_list[-1...][0].created_utc 
    else (Math.ceil(Date.now() / 1000) - @_startup_window)
    await @go_back stop, defer err
    cb err

  #---------------------------

  start_scraper_loop : ({scraper}, cb) ->
    @_scraper = scraper
    await @scrape defer err
    @_running = true
    cb err
    loop
      await setTimeout defer(), @_delay
      await @scrape defer()

  #---------------------------

  find : ( {scraper, username}, cb) ->
    err = out = null
    await @_lock.acquire defer()
    if not @_running
      await @start_scraper_loop {scraper}, defer err
    @_lock.release()
    rc = if err? then @_last_rc 
    else if (out = @_cache[username])? then v_codes.OK
    else v_codes.NOT_FOUND
    cb err, rc, out

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

  hunt2 : ({username, proof_text_check, name}, cb) ->
    rc  = v_codes.OK
    out = {}
    if not (err = @_check_args { username, name })?
      await @_global_hunter.find { scarper : @, username}, defer err, rc, out
      if rc is v_codes.OK
        out =
          api_url : PREFIX + out.data.permalink + ".json"
          human_url : PREFIX + out.data.permalink
          remote_id : out.data.name
    else
      rc = v_codes.BAD_USERNAME
    out.rc = rc
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    rxx = new RegExp("^#{SUBREDDIT}", "i")
    return (api_url? and api_url.match(rxx));

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the payload_text_check matches the sig.
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode signature
    if not err?
      {med_id} = make_ids msg.body
      if proof_text_check.indexOf(med_id) < 0
        err = new Error "Bad payload text_check"
    return err

  # ---------------------------------------------------------------------------

  unpack_data : (json) ->
    if (json[0]?.kind is 'Listing') and ((parent = json[0]?.data?.children?[0])?.kind is 't3')
      parent.data
    else
      null

  # ---------------------------------------------------------------------------

  check_data : ({json, username, proof_text_check, med_id }) ->
    if not (json.subreddit? and json.author? and json.selftext?) then v_codes.CONTENT_FAILURE
    else if (json.subreddit.toLowerCase() isnt 'keybaseproofs') then v_codes.CONTENT_FAILURE
    else if (json.author.toLowerCase() isnt username.toLowerCase()) then v_codes.BAD_USERNAME
    else if (json.author.title.indexOf(med_id) < 0) then v_codes.MISSING
    else if (json.selftext.indexOf(proof_text_check) < 0) then v_codes.MISSING
    else v_codes.OK

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->

    {med_id} = make_ids(new Buffer proof_text_check, 'base64')

    # calls back with a v_code or null if it was ok
    await @_get_url_body { url : api_url , json : true }, defer err, rc, json

    rc = if rc isnt v_codes.OK then rc
    else if not (dat = @unpack_data(json)) then v_codes.CONTENT_FAILURE
    else @check_data {json, username, proof_text_check, med_id }
    cb err, rc

#================================================================================

