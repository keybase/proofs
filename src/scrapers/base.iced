
{constants} = require '../constants'
{v_codes} = constants

#==============================================================

class BaseScraper
  constructor : ({@libs}) ->

  hunt : (username, signature, cb) ->
  id_to_url : (username, status_id) ->
  check_status : ({username, url, signature, status_id}, cb) -> 

  #-------------------------------------------------------------

  validate : ( { url, username, sig, payload_text_check }, cb) ->
    err = null
    if not @_check_url { url, username } 
      err = new Error "check url failed for #{url}, #{username}"
    else
      await @_validate_text_check { sig, payload_text_check }, defer err
    cb err

  #-------------------------------------------------------------

  _get_url_body: (opts, cb) ->
    ###
      cb(err, body) only replies with body if status is 200
    ###
    body = null
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

