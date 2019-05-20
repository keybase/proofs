{cieq,Base} = require './base'
{constants} = require './constants'
urlmod = require 'url'

#==========================================================================

class WebServiceBinding extends Base

  #------

  _v_customize_json : (ret) ->
    ret.body.service = o if (o = @service_obj())?

  #---------------

  _service_obj_check : (x) -> return not(x?)

  #---------------

  # service has to be optional because some legacy sigchains
  # use this type to prove ownership of a new key with no
  # service section
  _optional_sections : () -> super().concat(["revoke", "service"])

  #---------------

  # For Twitter, Github, etc, this will be empty.  For non-signle-occupants,
  # it will be the unique id for the resource, like https://keybase.io/ for
  # Web services.
  resource_id : () -> ""

  #---------------

  _type : () -> constants.sig_types.web_service_binding

  #---------------

  _type_v2 : (revoke_flag) ->
    if @revoke? or revoke_flag then constants.sig_types_v2.web_service_binding_with_revoke
    else constants.sig_types_v2.web_service_binding

  #---------------

  _v_check : ({json}, cb) ->
    await super { json }, defer err
    if not(err?) and not(@_service_obj_check(json?.body?.service))
      err = new Error "Bad service object found"
    cb err

#==========================================================================

class SocialNetworkBinding extends WebServiceBinding

  _service_obj_check : (x) ->
    so = @service_obj()
    return (x? and cieq(so.username, x.username) and cieq(so.name, x.name))

  service_obj  : -> { name : @service_name(), username : @user.remote }
  is_remote_proof : () -> true

  @single_occupancy : () -> true
  single_occupancy  : () -> SocialNetworkBinding.single_occupancy()

  @normalize_name : (n) ->
    n = n.toLowerCase()
    if n[0] is '@' then n[1...] else n

  normalize_name : (n) ->
    n or= @user.remote
    if @check_name(n) then SocialNetworkBinding.normalize_name n
    else null

  check_inputs : () ->
    if (@check_name(@user.remote)) then null
    else new Error "Bad remote_username given: #{@user.remote}"

  to_key_value_pair : () ->
    { key : @service_name(), value : @normalize_name() }

#==========================================================================

# A last-minute sanity check of the URL module
has_non_ascii = (s) ->
  buf = Buffer.from s, 'utf8'
  for i in [0...buf.length]
    if buf.readUInt8(i) >= 128
      return true
  return false

#----------

class GenericWebSiteBinding extends WebServiceBinding

  constructor : (args) ->
    @remote_host = @parse args.remote_host
    super args

  @parse : (h, opts = {}) ->
    ret = null
    if h? and (h = h.toLowerCase())? and (o = urlmod.parse(h))? and
        o.hostname? and (not(o.path?) or (o.path is '/')) and not(o.port?)
      protocol = o.protocol or opts.protocol
      if protocol?
        ret = { protocol, hostname : o.hostname }
        n = GenericWebSiteBinding.to_string(ret)
        if has_non_ascii(n)
          console.error "Bug in urlmod found: found non-ascii in URL: #{n}"
          ret = null
    return ret

  parse : (h) -> GenericWebSiteBinding.parse h

  to_key_value_pair : () -> {
    key : @remote_host.protocol[0...-1]
    value : @remote_host.hostname
  }

  @to_string : (o) ->
    ([ o.protocol, o.hostname ].join '//').toLowerCase()

  @normalize_name : (s) ->
    if (o = GenericWebSiteBinding.parse(s))? then GenericWebSiteBinding.to_string(o) else null

  @check_name : (h) -> GenericWebSiteBinding.parse(h)?
  check_name : (n) -> @parse(n)?

  @single_occupancy : () -> false
  single_occupancy  : () -> GenericWebSiteBinding.single_occupancy()

  resource_id : () -> @to_string()

  to_string : () -> GenericWebSiteBinding.to_string @remote_host

  _service_obj_check : (x) ->
    so = @service_obj()
    return x? and so? and cieq(so.protocol, x.protocol) and cieq(so.hostname, x.hostname)

  service_obj     : () -> @remote_host
  is_remote_proof : () -> true
  proof_type      : () -> constants.proof_types.generic_web_site
  @name_hint      : () -> "a valid hostname, like `my.site.com`"

  check_inputs : () ->
    if @remote_host? then null
    else new Error "Bad remote_host given"

  check_existing : (proofs) ->
    if (v = proofs.generic_web_site)?
      for {check_data_json} in v
        if cieq(GenericWebSiteBinding.to_string(check_data_json), @to_string())
          return new Error "A live proof for #{@to_string()} already exists"
    return null

#==========================================================================

class DnsBinding extends WebServiceBinding

  constructor : (args) ->
    @domain = @parse args.remote_host
    super args

  @parse : (h, opts = {}) ->
    ret = null
    if h?
      h = "dns://#{h}" if h.indexOf("dns://") isnt 0
      if h? and (h = h.toLowerCase())? and (o = urlmod.parse(h))? and
          o.hostname? and (not(o.path?) or (o.path is '/')) and not(o.port?)
        ret = o.hostname
        if has_non_ascii(ret)
          console.error "Bug in urlmod found: non-ASCII in done name: #{ret}"
          ret = null
    return ret

  to_key_value_pair : () -> { key : "dns", value : @domain }

  parse : (h) -> DnsBinding.parse(h)
  @to_string : (o) -> o.domain
  to_string : () -> @domain
  normalize_name : (s) -> DnsBinding.parse(s)
  @single_occupancy : () -> false
  single_occupancy : () -> DnsBinding.single_occupancy()
  resource_id : () -> @to_string()
  _service_obj_check : (x) ->
    so = @service_obj()
    return x? and so? and cieq(so.protocol, x.protocol) and cieq(so.domain, x.domain)
  @service_name : -> "dns"
  service_name  : -> @constructor.service_name()
  proof_type : -> constants.proof_types.dns
  @check_name : (n) -> DnsBinding.parse(n)?
  check_name : (n) -> DnsBinding.check_name(n)
  service_obj : () -> { protocol : "dns", @domain }
  is_remote_proof : () -> true
  check_inputs : () -> if @domain then null else new Error "Bad domain given"
  @name_hint : () -> "A DNS domain name, like maxk.org"

  check_existing : (proofs) ->
    if (v = proofs.dns?)
      for {check_data_json} in v
        if cieq(GenericWebSiteBinding.to_string(check_data_json), @to_string())
          return new Error "A live proof for #{@to_string()} already exists"
    return null

#==========================================================================

class TwitterBinding extends SocialNetworkBinding

  @service_name : -> "twitter"
  service_name  : -> @constructor.service_name()
  proof_type    : -> constants.proof_types.twitter
  is_short      : -> true

  @check_name : (n) ->
    ret = if not n? or not (n = n.toLowerCase())? then false
    else if n.match /^[a-z0-9_]{1,20}$/ then true
    else false
    return ret

  check_name : (n) -> TwitterBinding.check_name(n)

  @name_hint : () -> "alphanumerics, between 1 and 15 characters long"

#==========================================================================

class FacebookBinding extends SocialNetworkBinding

  @service_name : -> "facebook"
  service_name  : -> @constructor.service_name()
  proof_type    : -> constants.proof_types.facebook
  is_short      : -> true

  @check_name : (n) ->
    # Technically Facebook doesn't count dots in the character count, and also
    # prohibits leading/trailing/consecutive dots.
    ret = if not n? or not (n = n.toLowerCase())? then false
    else if n.match /^[a-z0-9.]{1,50}$/ then true
    else false
    return ret

  check_name : (n) -> FacebookBinding.check_name(n)

  @name_hint : () -> "alphanumerics and dots, between 1 and 50 characters long"

#==========================================================================

class KeybaseBinding extends WebServiceBinding

  _service_obj_check  : (x) -> not x?
  @service_name       : -> "keybase"
  service_name        : -> @constructor.service_name()
  proof_type          : -> constants.proof_types.keybase
  service_obj         : ->  null

#==========================================================================

class GithubBinding extends SocialNetworkBinding
  @service_name : -> "github"
  service_name  : -> @constructor.service_name()
  proof_type    : -> constants.proof_types.github

  @check_name : (n) ->
    if not n? or not (n = n.toLowerCase())? then false
    else if n.match /^[a-z0-9][a-z0-9-]{0,38}$/ then true
    else false

  @name_hint : () -> "alphanumerics, between 1 and 39 characters long"
  check_name : (n) -> GithubBinding.check_name(n)

#==========================================================================

class RedditBinding extends SocialNetworkBinding
  @service_name : -> "reddit"
  service_name  : -> @constructor.service_name()
  proof_type    : -> constants.proof_types.reddit

  @check_name : (n) ->
    if not n? or not (n = n.toLowerCase())? then false
    else if n.match /^[a-z0-9_-]{3,20}$/ then true
    else false

  @name_hint : () -> "alphanumerics, between 3 and 20 characters long"
  check_name : (n) -> RedditBinding.check_name(n)

#==========================================================================

class CoinbaseBinding extends SocialNetworkBinding
  @service_name : -> "coinbase"
  service_name  : -> @constructor.service_name()
  proof_type    : -> constants.proof_types.coinbase

  @check_name : (n) ->
    if not n? or not (n = n.toLowerCase())? then false
    else if n.match /^[a-z0-9_]{2,16}$/ then true
    else false

  @name_hint : () -> "alphanumerics, between 2 and 16 characters long"
  check_name : (n) -> CoinbaseBinding.check_name(n)

#==========================================================================

class HackerNewsBinding extends SocialNetworkBinding
  @service_name : -> "hackernews"
  service_name  : -> @constructor.service_name()
  proof_type    : -> constants.proof_types.hackernews

  @check_name : (n) ->
    if not n? or not (n = n.toLowerCase())? then false
    else if n.match /^[a-z0-9_-]{2,15}$/ then true
    else false
  @name_hint : () -> "alphanumerics, between 2 and 15 characters long"
  check_name : (n) -> HackerNewsBinding.check_name(n)

  # HN names are case-sensitive
  @normalize_name : (n) ->
    if n[0] is '@' then n[1...] else n
  normalize_name : (n) ->
    n or= @user.remote
    if @check_name(n) then HackerNewsBinding.normalize_name n
    else null
  _service_obj_check : (x) ->
    so = @service_obj()
    return (x? and (so.username is x.username) and cieq(so.name, x.name))

#==========================================================================

class GenericSocialBinding extends SocialNetworkBinding
  constructor : (args) ->
    @remote_service = args.remote_service
    if (r = args.name_regexp)? then try @name_regexp = new RegExp(r)
    super args

  @single_occupancy : () -> false
  single_occupancy  : () -> GenericSocialBinding.single_occupancy()

  service_name : -> @remote_service
  proof_type   : -> constants.proof_types.generic_social

  check_name : (n) ->
    unless n? and (n is n.toLowerCase()) then false
    else if n.match @name_regexp then true
    else false

  @name_hint : () -> "valid username"

  @_check_remote_service : (n) ->
    unless n? and (n is n.toLowerCase()) then false
    else if n.match /^([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,15}?$/ then true
    else false
  _check_remote_service : (n) -> GenericSocialBinding._check_remote_service(n)

  check_inputs : () ->
    if err = super() then return err
    else if not(@remote_service?) then return new Error "No remote_service given"
    else if not(@_check_remote_service(@remote_service)) then return new Error "invalid remote_service"
    else if not(@name_regexp?) then return new Error "No name_regexp given"
    else return null

  resource_id : () -> @remote_service

exports.TwitterBinding = TwitterBinding
exports.FacebookBinding = FacebookBinding
exports.RedditBinding = RedditBinding
exports.KeybaseBinding = KeybaseBinding
exports.GithubBinding = GithubBinding
exports.GenericWebSiteBinding = GenericWebSiteBinding
exports.CoinbaseBinding = CoinbaseBinding
exports.DnsBinding = DnsBinding
exports.HackerNewsBinding = HackerNewsBinding
exports.SocialNetworkBinding = SocialNetworkBinding
exports.GenericSocialBinding = GenericSocialBinding

#==========================================================================
