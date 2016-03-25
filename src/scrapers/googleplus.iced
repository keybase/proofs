{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants

#================================================================================

exports.GooglePlusScraper = class GooglePlusScraper extends BaseScraper

  constructor: (opts) ->
    @auth = opts.auth
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not(args.username?)
      new Error "Bad args to Google Plus proof: no user ID given"
    else if not (args.name?) or (args.name isnt 'googleplus')
      new Error "Bad args to Google Plus proof: type is #{args.name}"
    else
      null

  # ---------------------------------------------------------------------------

  hunt2 : ({username, proof_text_check, name}, cb) ->

    # calls back with rc, out
    rc       = v_codes.OK
    out      = {}

    return cb(err,out) if (err = @_check_args { username, name })?

    url = "https://www.googleapis.com/plus/v1/people/#{username}/activities/public"
    await @_get_body url, true, defer err, rc, json
    @log "| search index #{url} -> #{rc}"
    if rc is v_codes.OK
      rc = v_codes.NOT_FOUND
      for post in json.items
        out = @_search_post { post, proof_text_check }
        break if out.rc is v_codes.OK
    out.rc or= rc
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    rxx = new RegExp("^https://plus.google.com/#{username}/posts/", "i")
    return (api_url? and api_url.match(rxx));

  # ---------------------------------------------------------------------------

  _search_post : ({post, proof_text_check}) ->
    out = {}
    if not ((u = post.url) and (object = post.object))?
      @log "| post didn't have a URL or object"
      rc = v_codes.FAILED_PARSE
    else
      console.log("got object", object)
      if @_find_sig_in_raw(proof_text_check, object.content)
            @log "| search -> found"
            rc = v_codes.OK
            out =
              api_url : post.url
              remote_id : post.id
              human_url : post.url
    out.rc = rc
    out

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->

    # calls back with a v_code or null if it was ok
    await @_get_body "https://www.googleapis.com/plus/v1/activities/" + remote_id, true, defer err, rc, out
    console.log("OUT")
    console.log(out)
    if not ((object = out.object) and (raw = object.content))
      rc = v_codes.FAILED_PARSE
    else
      ptc_buf = new Buffer proof_text_check, "base64"
      rc = if rc isnt v_codes.OK                       then rc
      else if @_find_sig_in_raw(proof_text_check, raw) then v_codes.OK
      else                                                  v_codes.NOT_FOUND
    cb err, rc

  # ---------------------------------------------------------------------------

  _get_body : (url, json, cb) ->
    @log "| HTTP request for URL '#{url}'"
    args =
      url : url + "?key=" + @auth
      #auth : @auth
    console.log args
    args.json = true if json
    @_get_url_body args, cb

#================================================================================

