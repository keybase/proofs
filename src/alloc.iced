
web_service = require './web_service'
base = require './base'
{Untrack,Track} = require './track'
{Auth} = require './auth'
{Revoke} = require './revoke'
{Cryptocurrency} = require './cryptocurrency'
{Announcement} = require './announcement'
{Subkey} = require './subkey'
{Sibkey} = require './sibkey'
{Stellar} = require './wallet'
{PerUserKey} = require './per_user_key'
{Device} = require './device'
{Eldest} = require './eldest'
{PGPUpdate} = require './pgp_update'
{UpdatePassphraseHash} = require './update_passphrase_hash'
{UpdateSettings} = require './update_settings'
team = require './team'
team_hidden = require './team_hidden'
wot = require './wot'

#=======================================================

lookup_tab = {
  "web_service_binding.twitter"        : web_service.TwitterBinding,
  "web_service_binding.facebook"       : web_service.FacebookBinding,
  "web_service_binding.github"         : web_service.GithubBinding,
  "web_service_binding.reddit"         : web_service.RedditBinding,
  "web_service_binding.keybase"        : web_service.KeybaseBinding,
  "web_service_binding.generic"        : web_service.GenericWebSiteBinding,
  "web_service_binding.dns"            : web_service.DnsBinding,
  "web_service_binding.coinbase"       : web_service.CoinbaseBinding,
  "web_service_binding.hackernews"     : web_service.HackerNewsBinding,
  "web_service_binding.generic_social" : web_service.GenericSocialBinding,

  "generic_binding"                : base.GenericBinding,
  "track"                          : Track,
  "untrack"                        : Untrack,
  "auth"                           : Auth,
  "revoke"                         : Revoke,
  "cryptocurrency"                 : Cryptocurrency,
  "announcement"                   : Announcement,
  "subkey"                         : Subkey,
  "sibkey"                         : Sibkey
  "per_user_key"                   : PerUserKey
  "wallet.stellar"                 : Stellar
  "device"                         : Device
  "eldest"                         : Eldest
  "pgp_update"                     : PGPUpdate
  "update_passphrase_hash"         : UpdatePassphraseHash
  "update_settings"                : UpdateSettings
  "team.index"                     : team.Index
  "team.root"                      : team.Root
  "team.new_subteam"               : team.NewSubteam
  "team.change_membership"         : team.ChangeMembership
  "team.rotate_key"                : team.RotateKey
  "team.leave"                     : team.Leave
  "team.subteam_head"              : team.SubteamHead
  "team.rename_subteam"            : team.RenameSubteam
  "team.invite"                    : team.Invite
  "team.rename_up_pointer"         : team.RenameUpPointer
  "team.delete_root"               : team.DeleteRoot
  "team.delete_subteam"            : team.DeleteSubteam
  "team.delete_up_pointer"         : team.DeleteUpPointer
  "team.kbfs"                      : team.KBFS
  "team.settings"                  : team.Settings
  "team.bot_settings"              : team.BotSettings
  "wot.vouch"                      : wot.Vouch
  "wot.react"                      : wot.React
}

#--------------------------------------------

get_klass = (type, extra_lookup_tab) ->
  err = klass = null
  unless (klass = extra_lookup_tab?[type])? or (klass = lookup_tab[type])?
    err = new Error "Unknown proof class: #{type}"
  [err, klass]

#=======================================================

alloc = (type, args, extra_lookup_tab) ->
  ret = null
  [err, klass] = get_klass type, extra_lookup_tab
  if klass?
    ret = new klass args
  ret

#=======================================================

exports.get_klass = get_klass
exports.alloc = alloc

#=======================================================
