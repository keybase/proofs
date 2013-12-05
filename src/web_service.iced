kbpgp = require 'kbpgp'
{Base} = require './base'
{constants} = require './constants'
{bufeq_secure,unix_time} = kbpgp.util

#==========================================================================

class WebServiceBinding extends Base

  #------

  _json : () ->
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
    await super { json }, defer err
    unless err?
      err = if @_service_obj_check json?.body?.service 
        new Error "Bad service object found"
    cb err

#==========================================================================

class RemoteBinding extends WebServiceBinding

  _service_obj_check : (x) ->
    so = @service_obj()
    return (x? and (so.username is x.username) and (so.name is x.name))

  service_obj  : -> { name : @service_name(), username : @user.remote }
  is_remote_proof : () -> false

#==========================================================================

class TwitterBinding extends RemoteBinding

  service_name : -> "twitter"
  proof_type   : -> constants.proof_types.twitter

#==========================================================================

class KeybaseBinding extends WebServiceBinding

  _service_obj_check : (x) -> not x? 
  service_name       : -> "keybase"
  proof_type         : -> constants.proof_types.keybase
  service_obj        : ->  null

#==========================================================================

class GithubBinding extends RemoteBinding
  service_name : -> "github"
  proof_type   : -> constants.proof_types.github

#==========================================================================

exports.TwitterBinding = TwitterBinding
exports.KeybaseBinding = KeybaseBinding
exports.GithubBinding = GithubBinding

#==========================================================================
