kbpgp = require 'kbpgp'
{Base} = require './base'
{constants} = require './constants'
{unix_time} = kbpgp.util

#==========================================================================

class WebServiceBinding extends Base

  constructor : ({km, @seqno, @username, @host}) ->
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
          username : @username.remote
        key :
          host : @host
          username : @username.local
          key_id : @km.get_pgp_key_id().toString('hex')
          fingerprint : @km.get_pgp_fingerprint().toString('hex')
    }

  #---------------

  _v_check : ({json}, cb) -> 
    err = if (a = json?.body?.type) isnt (b = constants.sig_types.web_service_binding)
      new Error "Wrong signature type; got '#{a}' but wanted '#{b}'"
    else if (a = json?.body?.service) isnt (b = @service_name())
      new Error "Wrong service name; got '#{a}' but wanted '#{b}'"
    else
      null

#==========================================================================

class TwitterBinding extends WebServiceBinding

  service_name : -> "twitter.com"

#==========================================================================

exports.TwitterBinding = TwitterBinding

#==========================================================================
