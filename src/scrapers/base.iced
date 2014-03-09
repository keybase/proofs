
{constants} = require '../constants'
{v_codes} = constants

#==============================================================

class BaseScraper
  constructor : ({@libs}) ->

  hunt : (username, signature, cb) ->
  hunt2 : ({username, signature, log}, cb) ->
  id_to_url : (username, status_id) ->
  check_status : ({username, url, signature, status_id}, cb) -> 

  #-------------------------------------------------------------

  validate : ({api_url, username, signature, proof_text_check, remote_id} , cb) -> 
    err = null
    rc = null
    if not @_check_api_url { api_url, username }
      err = new Error "check url failed for #{api_url}, #{username}"
    else
      err = @_validate_text_check  { signature, proof_text_check }
    unless err?
      await @check_status { 
        signature : proof_text_check,
        username,
        api_url,
        remote_id
      }, defer err, rc
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

