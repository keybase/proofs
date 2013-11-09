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
    return {
      tag : constants.tags.sig
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
        date : unix_time()
        expire_in : constants.expire_in
        seqno : @seqno
    }

#==========================================================================

class TwitterBinding extends WebServiceBinding

  service_name : -> "twitter.com"

#==========================================================================

exports.TwitterBinding = TwitterBinding

#==========================================================================
