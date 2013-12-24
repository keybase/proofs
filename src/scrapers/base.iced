
{constants} = require '../constants'
{v_codes} = constants

#==============================================================

class BaseScraper
  constructor : ({@libs}) ->

  hunt : (username, signature, cb) ->
  id_to_url : (username, status_id) ->
  check_status : ({username, url, signature, status_id}, cb) -> 

  #-------------------------------------------------------------

  # Obj should have: { api_url, username, sig, proof_text_check, remote_id }
  validate : (obj, cb) -> 
    err = null
    rc = null
    if not @_check_api_url obj
      err = new Error "check url failed for #{url}, #{username}"
    else
      await @_validate_text_check obj, defer err
    unless err?
      await @check_status obj, defer err, rc
    cb err, rc

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

