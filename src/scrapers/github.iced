{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants

#================================================================================

exports.GithubScraper = class GithubScraper extends BaseScraper

  constructor: (opts) ->
    @auth = opts.auth
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not(args.username?)
      new Error "Bad args to Github proof: no username given"
    else if not (args.name?) or (args.name isnt 'github')
      new Error "Bad args to Github proof: type is #{args.name}"
    else
      null

  # ---------------------------------------------------------------------------

  hunt2 : ({username, proof_text_check, name}, cb) ->

    # calls back with rc, out
    rc       = v_codes.OK
    out      = {}

    return cb(err,out) if (err = @_check_args { username, name })?

    url = "https://api.github.com/users/#{username}/gists"
    await @_get_body url, true, defer err, rc, json
    @log "| search index #{url} -> #{rc}"
    if rc is v_codes.OK
      rc = v_codes.NOT_FOUND
      for gist in json
        await @_search_gist { gist, proof_text_check, gh_username: username }, defer out
        break if out.rc is v_codes.OK
    out.rc or= rc
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,username}) ->
    rxx = new RegExp("^https://gist.github(usercontent)?\\.com/#{username}/", "i")
    return (api_url? and api_url.match(rxx));

  # ---------------------------------------------------------------------------

  _search_gist : ({gist, proof_text_check, gh_username}, cb) ->
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
          content_norm = replace_all_whitespace(content).trim()
          escaped_gh_username = regex_escape(gh_username)
          # The common header.
          header1 = new RegExp("^### Keybase proof I hereby claim: \\* I am #{escaped_gh_username} on github\\. \\* I am \\w+ \\(https://keybase\\.io/\\w+\\) on keybase\\. ", "i")
          # The old header, possibly only used by Max :p
          header2 = new RegExp("^### Verifying myself: I am (https://keybase\\.io/)?\\w+ As part of this verification process, I am signing this object and posting as a gist as github user \\*#{escaped_gh_username}\\* ", "i")
          if not content_norm.match(header1) and not content_norm.match(header2)
            @log "| search #{filename} -> no claim"
            continue
          image_regex = new RegExp("!\\[", "i")
          if content.match(image_regex)
            @log "| search #{filename} -> gist contains an image"
            continue
          if @_find_sig_in_raw(proof_text_check, content)
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

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->

    # calls back with a v_code or null if it was ok
    await @_get_body api_url, false, defer err, rc, raw

    ptc_buf = new Buffer proof_text_check, "base64"
    rc = if rc isnt v_codes.OK                       then rc
    else if @_find_sig_in_raw(proof_text_check, raw) then v_codes.OK
    else                                                  v_codes.NOT_FOUND
    cb err, rc

  # ---------------------------------------------------------------------------

  _get_body : (url, json, cb) ->
    @log "| HTTP request for URL '#{url}'"
    args =
      url : url
      auth : @auth
    args.json = 1 if json
    @_get_url_body args, cb

#================================================================================

# Make it easier to match multi-line strings, by just replacing all whitespace
# runs (including newlines) with a single space.
replace_all_whitespace = (s) ->
  s.replace(/\s+/g, " ")

# https://stackoverflow.com/a/3561711/823869
regex_escape = (s) ->
    s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
