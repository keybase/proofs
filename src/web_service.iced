{Base} = require './base'
{constants} = require './constants'
urlmod = require 'url'

#==========================================================================

class WebServiceBinding extends Base

  #------

  _json : () ->
    ret = super {}
    ret.body.service = o if (o = @service_obj())?
    return ret

  #---------------

  _service_obj_check : (x) -> return not(x?)

  #---------------

  _type : () -> constants.sig_types.web_service_binding

  #---------------

  _v_check : ({json}, cb) -> 
    await super { json }, defer err
    unless err?
      err = if not @_service_obj_check json?.body?.service 
        new Error "Bad service object found"
    cb err

#==========================================================================

class SocialNetworkBinding extends WebServiceBinding

  _service_obj_check : (x) ->
    so = @service_obj()
    return (x? and (so.username is x.username) and (so.name is x.name))

  service_obj  : -> { name : @service_name(), username : @user.remote }
  is_remote_proof : () -> true

#==========================================================================

cieq = (a,b) -> (a.toLowerCase() is b.toLowerCase())

class GenericWebSiteBinding extends WebServiceBinding

  constructor : (args) ->
    @remote_host = @parse args.remote_host
    super args

  @parse : (h) ->
    ret = null
    if h? and (h = h.toLowerCase())? and (o = urlmod.parse(h))?
      ret = { protocol : o.protocol, hostname : o.hostname }
    return ret

  @to_string : (o) ->
    [ o.protocol, o.hostname ].join '://'

  parse : (h) -> GenericWebSiteBinding.parse h
  to_string : () -> GenericWebSiteBinding.to_string @remote_host

  _service_obj_check : (x) ->
    so = @service_obj()
    return x? and so? and cieq(so.procotol, x.protocol) and cieq(so.hostname, x.hostname)

  service_obj     : () -> @remote_host
  is_remote_proof : () -> true
  proof_type      : () -> constants.proof_types.generic_web_site

#==========================================================================

class TwitterBinding extends SocialNetworkBinding

  service_name : -> "twitter"
  proof_type   : -> constants.proof_types.twitter

#==========================================================================

class KeybaseBinding extends WebServiceBinding

  _service_obj_check : (x) -> not x?
  service_name       : -> "keybase"
  proof_type         : -> constants.proof_types.keybase
  service_obj        : ->  null

#==========================================================================

class GithubBinding extends SocialNetworkBinding
  service_name : -> "github"
  proof_type   : -> constants.proof_types.github

#==========================================================================

exports.TwitterBinding = TwitterBinding
exports.KeybaseBinding = KeybaseBinding
exports.GithubBinding = GithubBinding
exports.GenericWebSiteBinding = GenericWebSiteBinding

#==========================================================================
