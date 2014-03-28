{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{decode} = require('pgp-utils').armor
urlmod = require 'url'
{make_ids} = require '../base'
urlmod = require 'url'
dns = require 'dns'

#================================================================================

exports.make_TXT_record = (z) -> "keybase-validate=#{z}"

#================================================================================

exports.DnsScraper = class DnsScraper extends BaseScraper

  # ---------------------------------------------------------------------------

  constructor: (opts) ->
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not (args.domain?) then new Error "Bad args to DNS proof: no domain given"
    else null

  # ---------------------------------------------------------------------------

  make_url : ({domain}) -> "dns://#{domain.toLowerCase()}"
  url_to_domain : (u) -> urlmod.parse(u)?.hostname

  # ---------------------------------------------------------------------------

  hunt2 : ({domain}, cb) ->
    err = null
    if not domain?
      err = new Error "invalid arguments: expected a domain"
    else 
      url = @make_url { domain }
      out =
        api_url   : url
        human_url : url
        remote_id : url
        rc        : v_codes.OK
    cb err, out

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url,domain}) ->
    return (api_url.toLowerCase().indexOf(@make_domain {domain}) >= 0)

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the payload_text_check matches the sig.
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode signature
    if not err?
      {med_id} = make_ids msg.body
      if proof_text_check isnt make_TXT_record(med_id)
        err = new Error "Bad payload text_check"
    return err

  # ---------------------------------------------------------------------------

  check_status: ({protocol, hostname, api_url, proof_text_check}, cb) ->
    # calls back with a v_code or null if it was ok
    d = url_to_domain(api_url)
    if d? then new Error "no domain found in URL #{api_url}"
    else
      await dns.resolveTxt domain, defer err, records
      if err?              then # noop
      else if d in records then v_codes.OK
      else                      v_codes.NOT_FOUND
    cb err, rc

#================================================================================

