kbpgp = require 'kbpgp'
{Base} = require './base'
{constants} = require './constants'
{bufeq_secure,unix_time} = kbpgp.util

#==========================================================================

class WebServiceBinding extends Base

  constructor : ({km, @seqno, @user, @host}) ->
    super { km }

  #------

  json : () ->
    ret = { 
      seqno : @seqno
      body : 
        version : constants.versions.sig
        type : constants.sig_types.web_service_binding
        key :
          host : @host
          username : @user.local.username
          uid : @user.local.uid
          key_id : @km.get_pgp_key_id().toString('hex')
          fingerprint : @km.get_pgp_fingerprint().toString('hex')
    }
    ret.body.service = o if (o = @service_obj())?
    super ret

  #---------------

  _service_obj_check : (x) -> return not(x?)

  #---------------

  _v_check : ({json}, cb) -> 
    err = if (a = json?.body?.key?.username) isnt (b = @user.local.username)
      new Error "Wrong local user: got '#{a}' but wanted '#{b}'"
    else if (a = json?.body?.key?.uid) isnt (b = @user.local.uid)
      new Error "Wrong local uid: got '#{a}' but wanted '#{b}'"
    else if (a = json?.body?.type) isnt (b = constants.sig_types.web_service_binding)
      new Error "Wrong signature type; got '#{a}' but wanted '#{b}'"
    else if not @_service_obj_check json?.body?.service 
      new Error "Bad service object found"
    else if not (kid = json?.body?.key?.key_id)?
      new Error "Needed a body.key.key_id but none given"
    else if not bufeq_secure @km.get_pgp_key_id(), (new Buffer kid, "hex")
      new Error "Verification key doesn't match packet (via key ID)"
    else if not (fp = json?.body?.key?.fingerprint)?
      new Error "Needed a body.key.fingerprint but none given"
    else if not bufeq_secure @km.get_pgp_fingerprint(), (new Buffer fp, "hex")
      new Error "Verifiation key doesn't match packet (via fingerprint)"
    else
      null
    cb err

#==========================================================================

class TwitterBinding extends WebServiceBinding

  _service_obj_check : (x) ->
    so = @service_obj()
    return (x? and (so.username is x.username) and (so.name is x.name))

  service_obj  : -> { name : "twitter.com", username : @user.remote }
  proof_type   : -> constants.proof_types.twitter

#==========================================================================

exports.TwitterBinding = TwitterBinding

#==========================================================================
