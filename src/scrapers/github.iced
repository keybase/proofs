{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants

#================================================================================

exports.GithubScraper = class GithubScraper extends BaseScraper

  constructor: ({@auth, libs}) ->
    super { libs } 

  # ---------------------------------------------------------------------------

  hunt: (username, signature, cb) ->
    # calls back with rc, out
    rc       = v_codes.OK
    out      = {}

    await @_get_body "https://api.github.com/users/#{username}/gists", true, defer err, rc, json
    if rc is v_codes.OK
      rc = v_codes.NOT_FOUND
      for gist in json 
        await @_search_gist gist, signature, defer out
        break if out.rc is v_codes.OK
    out.rc or= rc
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    return (api_url.indexOf("https://api.github.com/users/#{username}/gists") is 0)

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the payload_text_check matches the sig.
  _validate_text_check : ({sig, proof_text_check }) ->
    [err, msg] = decode sig
    if not err? and ("\n\n" + msg.raw()) isnt proof_text_check
      err = new Error "Bad payload text_check"
    return err

  # ---------------------------------------------------------------------------

  _search_gist : (gist_json_obj, sig, cb) ->
    out = {}
    if not (u = gist_json_obj.url)? then rc = v_codes.FAILED_PARSE
    else
      await @_get_body u, true, defer err, rc, json
      if rc isnt v_codes.OK then # noop
      else if not json.files? then rc = v_codes.FAILED_PARSE
      else
        rc = v_codes.NOT_FOUND
        for filename, file of json.files when (content = file.content)?
          if (id = content.indexOf(sig)) >= 0
            rc = v_codes.OK
            out = 
              api_url : file.raw_url
              remote_id : gist_json_obj.id
              human_url : gist_json_obj.html_url
            break
    out.rc = rc
    cb out

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, signature, remote_id}, cb) ->
    # calls back with a v_code or null if it was ok
    await @_get_body api_url, false, defer err, rc, raw
    rc = if rc isnt v_codes.OK           then rc
    else if (raw.indexOf signature) >= 0 then v_codes.OK
    else                                      v_codes.NOT_FOUND
    cb err, rc

  # ---------------------------------------------------------------------------

  _get_body : (url, json, cb) ->
    @libs.log.info "+ HTTP request for URL '#{url}'"
    args =
      url : url
      headers : 
        "User-Agent" : constants.user_agent
      auth : @auth
    args.json = 1 if json
    @_get_url_body args, cb

#================================================================================

