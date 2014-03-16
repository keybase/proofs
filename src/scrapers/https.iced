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

  make_url : ({protocol, hostname}) ->
    urlmod.format {
      hostname, 
      protocol,
      pathname : ".well-known/keybase.txt"
    }

  # ---------------------------------------------------------------------------

  hunt2 : ({hostname, protocol}, cb) ->
    err = null
    if not hostname? or not protocol? 
      err = new Error "invalid arguments: expected a hostname and protocol"
    else 
      url = @make_url { hostname, protocol }
      out =
        api_url : url
        human_url : url
        remote_id : url
        rc : v_codes.OK
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,hostname,protocol}) ->
    return (api_url.toLowerCase().find(host.toLowerCase()) is 0)

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the payload_text_check matches the sig.
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode signature
    if not err? and ("\n\n" + msg.payload + "\n") isnt proof_text_check
      err = new Error "Bad payload text_check"
    return err

  # ---------------------------------------------------------------------------

  check_status: ({api_url, signature}, cb) ->
    # calls back with a v_code or null if it was ok
    await @_get_url_body {url : api_url}, defer err, rc, raw
    rc = if rc isnt v_codes.OK           then rc
    else if (raw.indexOf signature) >= 0 then v_codes.OK
    else                                      v_codes.NOT_FOUND
    cb err, rc

#================================================================================

