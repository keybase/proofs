
{constants} = require '../constants'
{v_codes} = constants

#==============================================================

class BaseScraper
  constructor : ({@libs, log_level, @proxy, @ca}) ->
    @log_level = log_level or "debug"

  hunt : (username, proof_check_text, cb) -> hunt2 { username, proof_check_text }, cb
  hunt2 : (args, cb) -> cb new Error "unimplemented"
  id_to_url : (username, status_id) ->
  check_status : ({username, url, signature, status_id}, cb) -> 
  _check_args : () -> new Error "unimplemented"

  #-------------------------------------------------------------

  log : (msg) ->
    if (k = @libs.log)? and @log_level? then k[@log_level](msg)

  #-------------------------------------------------------------

  validate : (args, cb) ->
    err = null
    rc = null
    if not @_check_args args
      err = new Error "bad arguments to proof"
    else if not @_check_api_url args
      err = new Error "check url failed for #{JSON.stringify args}"
    else
      err = @_validate_text_check args
    unless err?
      await @check_status args, defer err, rc, display
    cb err, rc, display

  #-------------------------------------------------------------

  _get_url_body: (opts, cb) ->
    ###
      cb(err, body) only replies with body if status is 200
    ###
    body = null
    opts.proxy = @proxy if @proxy?
    opts.ca = @ca if @ca?
    await @libs.request opts, defer err, response, body
    rc = if err? then v_codes.HOST_UNREACHABLE
    else if (response.statusCode is 200) then v_codes.OK
    else if (response.statusCode >= 500) then v_codes.HTTP_500
    else if (response.statusCode >= 400) then v_codes.HTTP_400
    else if (response.statusCode >= 300) then v_codes.HTTP_300
    else                                      v_codes.HTTP_OTHER
    cb err, rc, body

  #--------------------------------------------------------------

#==============================================================

exports.BaseScraper = BaseScraper

#==============================================================

