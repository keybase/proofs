{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{decode} = require('pgp-utils').armor

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
    out =  null
    unless (err = @_check_args { username, name })?
      await @_global_hunter.find username, defer err, out
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    rxx = new RegExp("^https://www.reddit.com/r/keybase", "i")
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

  _search_gist : ({gist, proof_text_check}, cb) ->
    out = {}
    if not (u = gist.url)? 
      @log "| gist didn't have a URL"
      rc = v_codes.FAILED_PARSE
    else
      await @_get_body u, true, defer err, rc, json
      if rc isnt v_codes.OK then # noop
      else if not json.files? then rc = v_codes.FAILED_PARSE
      else
        rc = v_codes.NOT_FOUND
        for filename, file of json.files when (content = file.content)?
          if (id = @_stripr(content).indexOf(proof_text_check)) >= 0
            @log "| search #{filename} -> found"
            rc = v_codes.OK
            out = 
              api_url : file.raw_url
              remote_id : gist.id
              human_url : gist.html_url
            break
          else
            @log "| search #{filename} -> miss"
      @log "| search gist #{u} -> #{rc}"
    out.rc = rc
    cb out

  # ---------------------------------------------------------------------------

  unpack_data : (json) ->
    if (json[0]?.kind is 'Listing') and ((parent = json[0]?.data?.children?[0])?.kind is 't3')
      parent.data
    else
      null

  # ---------------------------------------------------------------------------

  check_data : ({json, username, proof_text_check }) ->
    if not (json.subreddit? and json.author? and json.title?) then v_codes.CONTENT_FAILURE
    else if (json.subreddit.toLowerCase() isnt 'keybase') then v_codes.CONTENT_FAILURE
    else if (json.author.toLowerCase() isnt username.toLowerCase()) then v_codes.BAD_USERNAME
    else if (json.title.indexOf(proof_text_check) < 0) then v_codes.PROOF_NOT_FOUND
    else v_codes.OK

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->

    # calls back with a v_code or null if it was ok
    await @_get_url_body { url : api_url , json : true }, defer err, rc, json

    rc = if rc isnt v_codes.OK then rc
    else if not (dat = @unpack_data(json)) then v_codes.CONTENT_FAILURE
    else @check_data {json, username, proof_text_check }
    cb err, rc

#================================================================================

