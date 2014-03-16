{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{decode} = require('pgp-utils').armor
urlmod = require 'url'

#================================================================================

exports.WebSiteScraper = class WebSiteScraper extends BaseScraper

  constructor: (opts) ->
    super opts

  # ---------------------------------------------------------------------------

  field_name : () -> "host"

  # ---------------------------------------------------------------------------

  make_url : ({protocol, hostname}) ->
    urlmod.format {
      hostname, 
      protocol,
      pathname : ".well-known/keybase.txt"
    }

  # ---------------------------------------------------------------------------

  hunt2 : ({hostname, protocol, signature}, cb) ->
    url = @make_url { host, protocol }
    out =
      api_url : url
      human_url : url
      remote_id : host
      rc : v_codes.OK
    cb null, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,host}) ->
    return (api_url.toLowerCase().find(host.toLowerCase()) is 0)

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the payload_text_check matches the sig.
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode signature
    if not err? and ("\n\n" + msg.payload + "\n") isnt proof_text_check
      err = new Error "Bad payload text_check"
    return err

  # ---------------------------------------------------------------------------

  _search_gist : ({gist, signature}, cb) ->
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
          if (id = content.indexOf(signature)) >= 0
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

  check_status: ({username, api_url, signature, remote_id}, cb) ->
    # calls back with a v_code or null if it was ok
    await @_get_body api_url, false, defer err, rc, raw
    rc = if rc isnt v_codes.OK           then rc
    else if (raw.indexOf signature) >= 0 then v_codes.OK
    else                                      v_codes.NOT_FOUND
    cb err, rc

  # ---------------------------------------------------------------------------

  _get_body : (url, json, cb) ->
    @log "| HTTP request for URL '#{url}'"
    args =
      url : url
      headers : 
        "User-Agent" : constants.user_agent
      auth : @auth
    args.json = 1 if json
    @_get_url_body args, cb

#================================================================================

