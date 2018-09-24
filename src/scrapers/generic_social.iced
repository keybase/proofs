{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants

exports.GenericSocialScraper = class GenericSocialScraper extends BaseScraper
  constructor : (opts) ->
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not(args.username?)
      new Error "Bad args to GenericSocialScraper proof: no username given"
    else
      null

  # ---------------------------------------------------------------------------

  hunt2 : ({username, name}, cb) ->
    out = {}
    bad_args_err = (e, rc) ->
      out.rc = if rc? then rc else v_codes.BAD_ARGS
      new Error "Bad args to GenericSocialScraper proofs" + if e then ": #{e}" else ""

    if not(username?)
      err = bad_args_err "no username given"
    else if not(name?)
      err = bad_args_err "no service name given"
    else if name.indexOf('.') is -1
      err = bad_args_err "service name `#{name}` is likely wrong - no dot in name."
    else if not @libs.get_service_obj?
      err = bad_args_err "@libs.get_service_obj is undefined"
    else if not (service_obj = @libs.get_service_obj(name))?
      err = bad_args_err "unknown service `#{name}`", v_codes.SERVICE_DEAD
    else
      out =
        rc : v_codes.OK
        api_url : service_obj.create_check_url { remote_username : username }
        remote_id : username

    cb err, out

  # ---------------------------------------------------------------------------

  _find_proofs_in_json : ({service_obj, obj, kb_username, sig_id}) ->
    rc = v_codes.NOT_FOUND
    err = null

    {check_path} = service_obj
    path = check_path.concat()
    while step = path.shift()
      obj = obj[step]
      break if not obj?

    unless obj? and Array.isArray obj
      err = new Error "did not find proof list on #{check_path.join('.')} in json data"
      return [err, rc]

    found = obj.find (x) -> x.kb_username is kb_username and x.sig_hash is sig_id
    if found?
      rc = v_codes.OK
    else
      err = new Error "user not found in proof list"
    return [err, rc]

  # ---------------------------------------------------------------------------

  check_status : ({kb_username, username, name, api_url, sig_id}, cb) -> 
    if not (service_obj = @libs.get_service_obj?(name))?
      return cb new Error("bad service name"), v_codes.SERVICE_DEAD

    url = service_obj.create_check_url { remote_username : username }
    await @_get_url_body { url }, defer err, rc, html
    if rc is v_codes.OK
      try
        obj = JSON.parse html
      catch e
        err = new Error "unable to parse JSON content: #{e.toString()}"
        rc = v_codes.CONTENT_FAILURE
      if not err
        [err, rc] = @_find_proofs_in_json { service_obj, obj, kb_username, sig_id }

    cb err, rc
