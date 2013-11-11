kbpgp = require 'kbpgp'
{Base} = require './base'
{constants} = require './constants'
{unix_time} = kbpgp.util

#==========================================================================

class WebServiceBinding extends Base

  constructor : ({km, @seqno, @usernames, @host}) ->
    super { km }

  #------

  json : () ->
    super { 
      seqno : @seqno
      body : 
        version : constants.versions.sig
        type : constants.sig_types.web_service_binding
        service :
          name : @service_name()
          username : @usernames.remote
        key :
          host : @host
          username : @usernames.local
          key_id : @km.get_pgp_key_id().toString('hex')
          fingerprint : @km.get_pgp_fingerprint().toString('hex')
    }

  #---------------

  _v_check : ({json}, cb) -> 
    err = if (a = json?.body?.key?.username) isnt (b = @usernames.local)
      new Error "Wrong local user: got '#{a}' but wanted '#{b}'"
    else if (a = json?.body?.type) isnt (b = constants.sig_types.web_service_binding)
      new Error "Wrong signature type; got '#{a}' but wanted '#{b}'"
    else if (a = json?.body?.service?.name) isnt (b = @service_name())
      new Error "Wrong service name; got '#{a}' but wanted '#{b}'"
    else if not bufeq_secure @km.get_pgp_key_id(), json?.body?.key?.key_id
      new Error "Verification key doesn't match packet (via key ID)"
    else if not bufeq_secure @km.get_pgp_fingerprint(), json?.body?.key?.fingerprint
      new Error "Verifiation key doesn't match packet (via fingerprint)"
    else
      null

#==========================================================================

class TwitterBinding extends WebServiceBinding

  service_name : -> "twitter.com"
  proof_type   : -> constants.proof_types.twitter

#==========================================================================

exports.TwitterBinding = TwitterBinding

#==========================================================================
