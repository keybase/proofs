## 2.3.13 (2020-01-14)

- WoT proof types
- generic stubbing support

## 2.3.12 (2019-12-04)

- different schema checkers for binary values bottom bytes
- also allow arrays to be empty if flagged

## 2.3.11 (2019-12-03)

- upgrade schema checkers for binary values

## 2.3.10 (2019-10-31)

- fix rate limit reporting

## 2.3.9 (2019-09-18)

- update facebook checker

## 2.3.8 (2019-09-10)

- report rate limit

## 2.3.7 (2019-08-01)

- small tweaks to team sig3, is_implicit and is_public bools are always there

## 2.3.6 (2019-07-24)
- add `bot_settings` signature type

## 2.3.5 (2019-07-10)
- bugfixes for featuresin 2.3.4

## 2.3.4 (2019-07-10)
- team rotate links now have admin pinning sections (as in the chain3 links)

## 2.3.3 (2019-06-25)
- export schema system, it's quite useful

## 2.3.2 (2019-06-10)
- fix issue where network timeouts were not being assigned the right error code
- small fixes to chain17 from testing

## 2.3.1 (2019-06-10)

- small tweaks from testing

## 2.3.0 (2019-05-30)

- use node-fetch instead of request in proof scraper
- add encryption parameters to sig3 schema

## 2.2.2 (2019-05-30)

-  multiple PTKs per RotateKey link now possible, though we'll only accept 1

## 2.2.1 (2019-05-23)

- public_chain -> parent_chain

## 2.2.0 (2019-05-15)

- Sig v3 first implementation, and RotateKey
- Tighten up defenses against malicious redirectors

## 2.1.68 (2019-04-30)

- Check types before comparing strings

## 2.1.67 (2019-03-09)

- Backout 2.1.66, which has a compiled dependency

## 2.1.65 (2019-02-01)

- Deprecate (new Buffer) and use Buffer.from

## 2.1.64 (2019-01-30)

- Static getters

## 2.1.61 and .62 and .63 (2018-12-02)

- NOOP, reverted feature

## 2.1.60 (2018-10-29)

- Upgrade bitcoyne to support sapling addresses

## 2.1.59 (2018-10-24)

- Fix subdomain validation in `GenericSocialBinding`

## 2.1.57-8 (2018-10-24)

- Allow subdomains in `GenericSocialBinding`

## 2.1.56 (2018-10-19)

- lowercase fix in GenericSocialScraper for `check_status`

## 2.1.55 (2018-10-04)

- GenericSocialScraper insists on lowercase inputs.

## 2.1.54 (2018-09-25)

- Add GenericSocialScraper.

## 2.1.53 (2018-09-24)

- Change constant

## 2.1.52 (2018-09-14)

- Bug fixes

## 2.1.51 (2018-09-12)

- Add `GenericSocialBinding` proof type, where `service_name` is not predefined.

## 2.1.50 (2018-09-05)

- Added specific error code for incorrect high skips.

## 2.1.48 (2018-09-05)

- Add support for `high_skip` fields to point to the last high link.

## 2.1.44

- Add an `appkey_derivation_version` field to the per_team_key section of team signatures

## 2.1.42-3 (2018-6-26)

- Tweak Reddit User-Agent

## 2.1.37-41 (2018-05-21)

- Twitter URI rewrite to mobile.twitter.com

## 2.1.36 (2018-05-21)

- Twitter change, so fix it

## 2.1.35 (2018-04-27)

- Do not ignore post body in reddit proofs

## 2.1.34 (2018-04-24)

- Ignore post body in reddit proofs

## 2.1.33 (2018-03-26)

- Rename wallet -> wallet.stellar
- Check that { "version" : 1 } is correct for V1 links (and we're not lying about it)

## 2.1.32 (2018-03-20)

- Check that the stellar account ID matches the signing wallet key

## 2.1.31 (2018-03-08)

- Add support for wallet keys

## 2.1.30 (2018-02-21)

- Bugfix in sigchainv2.

## 2.1.29 (2018-01-23)

- liberalize twitter hunt/scrape since now they emlinkify Keybase.io

## 2.1.28 (2018-01-22)

- tighten up GH regex

## 2.1.27 (2017-11-30)

- Retire code=45, from legacy_tlf_upgrade, and change kbfs settings to code=47

## 2.1.26 (2017-11-28)

- Legacy TLF upgrade -> KBFS in general (since we're also going to use it for TLF ID bindings)

## 2.1.24 (2017-11-03)

- Add `ignore_if_unsupported` bool for backwards compatible links

## 2.1.23 (2017-10-27)

- Be more paranoid about error strings, in case they ever wind up in HTML

## 2.1.22 (2017-10-23)

- Better error message for sequence number violations

## 2.1.17 (2017-09-05)

- legacy TLF upgrade links

## 2.1.16 (2017-07)

- change team.delete to team.delete_root and team.delete_subteam

## 2.1.15 (2017-07-24)

- team.delete and team.delete_up_pointer

## 2.1.14 (2017-06-14)

- team.rename_up_pointer

## 2.1.8 (2017-05-05)

- rename shared_dh -> per_user_key
- in PUK, above, include 2 types of keys: signing and encryption

## 2.1.7 (2017-05-02)

- expose unpacked outer also from proofs

## 2.1.6 (2017-05-01)

- Inner links now have version:2
- Check that the version out the outer matches the inner
- Fix bug in chainlink v2 verification

## 2.1.5 (2017-04-27)

Support for team.rename_subteam

## 2.1.4

Various team fixes

## 2.1.3

New features:
 - Basic and rough teams support

## 2.1.2

New Features:
 - Shared DH key support

## 2.1.1

Bugfix:
 - Wrong proof type for sibkeys in v2

## 2.1.0

Feature:
  - Support for V2 chainlinks

## 2.0.64 (2017-01-17)

Bugfix:
  - Facebook proof parsing got confused by names that looked like links.

## 2.0.63 (2016-12-16)

Bugfix:
  - The minimum username length for Facebook was too high.

## 2.0.62 (2016-12-13)

Feature:
  - Flag to skip critical clock skew check in C/I

## 2.0.61 (2016-12-13)

Bugfix:
 - Check that ctime is valid before checking etime

## 2.0.60 (2016-12-13)

Feature:
 - Disallow sigs that were created too far in the past or the future, i.e., if the user's
    clock is skewed.

## 2.0.59 (2016-11-11)

Bugfixes:
 - Handle crasher in logins with null email addresses

## 2.0.58 (2016-11-07)

Bufixes:
 - Handle -- decoding properly in Facebook proofs.

## 2.0.57 (2016-11-04)

Bufixes:
 - Facebook support that works even for private profiles.

## 2.0.56

Feature:
 - Better bitcoin checking, and add zcash support

## 2.0.55

Feature:
 - Add an update_settings signature type

## 2.0.54

Bugfixes:
 - Add fields for revoking

## 2.0.53 (2016-10-07)

Bugfixes:
 - Allow device revokes along with key revokes

## 2.0.52 (2016-09-16)

Bugfixes:
 - Make the Facebook username normalization handle dots properly.

## 2.0.51 (2016-09-08)

Bugfixes:
 - Make the Facebook CSS selectors stricter

## 2.0.50 (2016-09-01)

Bugfixes:
 - Fix FB usernames with digits in them >.<

## 2.0.49 (2016-08-29)

Features:
 - Preliminary Facebook support

## 2.0.48 (2016-06-15)

Features:
 - Better debugging for reddit

## 2.0.47 (2016-01-04)

Bugfix:
 - Make github base64-finder more lenient, so it works with windows-introduced newlines in keybase sig format

## 2.0.46 (2015-11-24)

Bugfixes:
  - Fix regressions in reddit proofs (missing _check_api_url function)

## 2.0.45 (2015-11-24)

Bugfixes:
  - Workaround new coinbase HTML style

## 2.0.44 (2015-09-25)

Features:
  - Bitbucket support (thanks to @mark-adams)
  - Allow 0-time expirations in sig gens

## 2.0.43 (2015-09-15)

Bugfix:
  - Unbreak the site, don't return our trimed JSON

## 2.0.42 (2015-09-15)

Bugfix:
  - Disregard trailing whitespace in JSON when checking for non-acceptable
    characters and strict-mode byte-for-byte comparison

## 2.0.41 (2015-09-10)

Enhancement:
  - Strict JSON checking

## 2.0.40 (2015-09-08)

Enhancement:
  * Use kbpgp to generate PGP key hashes

## 2.0.39 (2015-08-20)

Bugfix:
  * Fix a crash when generating `eldest` links.

## 2.0.38 (2015-08-20)

Bugfix:
  * `pgp_update` links now put PGP key metadata in a separate stanza instead of the `key` stanza.
  * PGP keys' fingerprints are validated now.

## 2.0.37 (2015-08-17)

Bugfix:
  * `pgp_update` links now take a dedicated KeyManager for the PGP key being updated

## 2.0.36 (2015-08-13)

Retired feature:
  * Strip out dualkey, they never made it into the wild

Feature:
  * Sigs which add PGP keys now include a hash of the armored key
  * Add a new sig type for updating PGP keys which also includes the full hash

## 2.0.35 (2015-08-12)

Bugfix:
  * Sometimes we just want a generic chainlink; in that case, don't worry about
    checking optional sections against the link-specific whitelist.

## 2.0.34 (2015-08-12)

Enhancement:
  * Add better error messages when invalid sections are found

## 2.0.33 (2015-08-06)

Fix embarrassment:
 * Rename internal methods in SubkeyBase to be more sensible

## 2.0.32 (2015-08-06)

Bugfix:
  * Update `eldest` and `revoke` statements to have an optional `device` section.

## 2.0.31 (2015-08-06)

Feature:
  * Each sigtype now has required and optional sections of the `body`. If there are `sections` in the body not that don't correspond to the sigtype, it will now be considered invalid.

Bugfix:
  * Update auth sigs to put `nonce` and `session` in `body.auth` instead of `body` directly.

## 2.0.30 (2015-07-24)

Bugfix:
  * Initially find Reddit proofs by looking at the user's submissions, not by scraping /r/KeybaseProofs

## 2.0.29 (2015-07-24)

Bugfix:
  * Bugfix in the previous, handle empty TXT lookups too

## 2.0.28 (2015-07-23)

Feature:
  * Allow third-party DNS library, so we can interoperate
    with broken Node v0.12 DNS TXT resolver: https://github.com/joyent/node/issues/9285

## 2.0.27 (2015-07-22)

Bugfixes:
  * For dualkey sigtype

## 2.0.26 (2015-07-21)

Bugfixes:
 * Fix crasher with reddit scraping

## 2.0.25

Security upgrade:
  * Require reverse sigs for sibkey

Features:
  * Allow dual sibkey/subkey provisioning, useful for single-transaction workflow in passphrase update.

## 2.0.24 (2015-06-15)

Features:
  * Allow update of passphrase via signed statement

## 2.0.23 (2015-05-15)

Features:
  - Allow an expanded lookup table of proof types, for testing purposes.

## 2.0.22 (2015-05-11)

Features:
  - Expose some hidden base classes for testing purposes.

## 2.0.21 (2015-05-06)

Features:
  - Allow `expire_in` for signatures
  - Allow passing `ctime` in for signatures, and actually use it
  - Add a `reverse_sig_check` method to Subkey that we can call directly.

## 2.0.20 (2015-04-03)

Bugfixes:
  - Allow revocation of keys via key-ids in sig links

## 2.0.19 (2015-03-24)

Bugfixes:
  - remove debug code
  - Cache the ctime on sig generation so that if we call @json()
    twice in the case of reverse sigs, we'll get the same blob both
    times.
Features:
  - pass back the reverse signature payload in sibkey signatures
  - Expand upon reverse sig; do it over the whole JSON object.

## 2.0.18 (2015-03-19)

Nit:
 - s/parent/delegated_by/.  This is a better name.

## 2.0.17 (2015-03-18)

Features:
  - Expanded reverse key signatures, and renamed fields.  This might
    break existing test data!

## 2.0.16 (2015-03-18)

Feature:
  - Use KMI.can_sign() and not KMI.get_keypair()?.can_sign()
    Only works in KBPGP v2.0.9 and above.

## 2.0.15 (2015-02-11)

Feature:
  - New sigchain link type: eldest, for your self-signed eldest key.
    It's synonymous with web_service_binding.keybase but
    should only happen at the start of a sigchain.

## 2.0.14 (2015-02-10)

Tweaks:
  - Session object in pubkey login

## 2.0.13 (2015-02-09)

Bugfixes:
  - the return format of dns.resolveTxt changed in Node v0.12.0;
    workaround it with this fix.  Should still work for earlier nodes.

## 2.0.12 (2015-01-30)

Tweaks:
  - Explicit parent_kid for subkeys

## 2.0.11 (2015-01-29)

Tweaks:
  - Strict reverse sig handling

## 2.0.10 (2015-01-29)

Security tweak:
  - Sign a more descriptive reverse-key signature

## 2.0.9 (2015-01-29)

Scraper tweak
  - Be more liberal about generic web sites; allow raw '\r's
    as line-ends

## 2.0.8 (2015-01-29)

Change:
 - move device up one level in the JSON structure

## 2.0.7 (2015-01-28)

Additions:
  - The 'device' signature

## 2.0.6 (2015-01-27)

Tweaks:
  - rename desc to device

## 2.0.5 (2015-01-18)

Tweaks:
   - Sibkey and subkey signatures have a "desc" field for description,
     not a "notes field"

## 2.0.4 (2015-01-14)

Bugfix with the previous fix

## 2.0.3 (2015-01-14)

Bugfixes:
  - Sometimes kids() can't be computed

## 2.0.2 (2015-01-14)

Features:
  - Sign `eldest_kid` into key blocks (Issue #15)

## 2.0.1 (2014-12-22)

Bufixes
  - Various

## 2.0.0 (2014-12-10)

Bugfix:
  - All @veganstraightedge to use his twitter handle (>15 chars)

New features:
  - lots of architectural improvements for keybase/keybase#204
    - Use either PGP or KB-style packets, sigs, and keys in all places.

## 1.1.3 (2014-09-21)

Nits:

  - Error message for cloudflare

## 1.1.2 (2014-09-20)

Bugfixes:

  - Make a better coinbase warning...

## 1.1.1 (2014-09-20)

Features:

  - Say if it is tor-safe or not. DNS and HTTP are not...

## 1.1.0 (2014-08-28)

Features:

  - New proof types for subkeys (think delegated app keys).
  - Begin to work in private sequences (need a separate type for those)

Bugfixes:

  - robustify _check_ids, and don't crash if short_id or id is null.

## 1.0.7 (2014-08-21)

Bugfixes:

  - Allow '0's in coinbase names. Thanks to @dtiersch for the PR.

## 1.0.6 (2014-08-18)

  - Yet more HackerNews fixes; only allow a proof posting if we can lookup their karma.
    For dummy users, the JSON endpoint will yield null, which means they won't be able to
    show their profile, either

## 1.0.5 (2014-08-14)

  - More HN fixes --- don't normalize usernames with toLowerCase();
    also warn that it's slow.

## 1.0.4 (2014-08-11)

  - Use the FireBase.io API for hackernews

## 1.0.3 (2014-08-05)

  - Hackernews logins are case-sensitive?
     - See here for more details: https://news.ycombinator.com/item?id=6963550
     - Resolves keybase/keybase-issues#911

## 1.0.2 (2014-08-04)

  - Bugfix for an HN failure with the command-line

## 1.0.1 (2014-08-04)

  - HackerNews

## 1.0.0 (2014-08-04)

  - Arbitrarily cut a 1.0.0 release
  - Use the correct UserAgent format
    - closes keybase/keybase-proofs#899
  - Reddit proofs
  - Coinbase proofs
  - Factor out some common code, but more work to go on this.

## 0.0.39  (2014-07-17)

  - More twitter API stuff

## 0.0.38 (2014-07-17)

Features:

  - twitter API calls to get follower_ids friend_ids

## 0.0.37 (2014-06-24)

Features:

  - ws_normalize in Twitter proofs.  Address keybase/keybase-issues#822

## 0.0.36 (2014-06-23)

Features:

  - Support for announcements

## 0.0.35 (2014-06-11)

Bugfix:

  - Don't include a `revoke : { sig_ids : [] }` stanza if we don't need it

## 0.0.34 (2014-06-10)

Bugfixes:

  - Fix a bug with revocation in which we weren't providing a default
    argument to _json(), which was crashing the proof generation.

## 0.0.33 (2014-06-09)

Features:

  - Add support for cryptocurrencies
  - Allow any signature to revoke previous signatures

## 0.0.32 (2014-06-05)

Features:

  - foo.com OR _keybase.foo.com are valid DNS TXT entries now...

## 0.0.30 and 0.0.31 (2014-06-04)

  - Recompile for ICS v1.7.1-c

## 0.0.29 (2014-05-15)

Bugfixes:

  - Better debug for keybase/keybase-issues#689

## 0.0.28 (2014-05-08)

Bufixes:

  - Address keybase/keybase-issues#695, don't hard-fail if .well-known is 403.

## 0.0.27 (2014-04-29)

Bugfixes:

  - Interpet HTTP 401 and 403 as permission denied errors

## 0.0.26 (2014-04-28)

Features:

  - Add merkle_root for all signatures

## 0.0.25 (2014-04-10)

Bugfixes:

  - Remove iced-utils dependency

## 0.0.24 (2014-04-09)

Features:

  - Support for DNS proofs
  - Support for foo.com/keybase.txt

## 0.0.23 (2014-04-05)

Bugfix:

  - Ensure that ctime and expire_in both exist.

## 0.0.22 (2014-04-02)

Bugfix:

  - Be more careful about timeouts

## 0.0.21 (2014-04-02)

Bugfix:

  - Error in the previous release, we need to allow some slack before the proof due to GPG
    client comments that might appear part of the signature block.

## 0.0.20 (2014-04-02)

Features:

  - Add the ability to sanity check the server's proof text

## 0.0.19 (2014-03-31)

Features:

  - Add Base::proof_type_str which just does a lookup against the lookup table

## 0.0.18 (2014-03-31)

Bugfixes:

  - Strip out debugging output

## 0.0.17 (2014-03-31)

Features:

  - Include some client information in proofs

## 0.0.16 (2014-03-29)

Features:

  - Add a new "generic_binding" type of proof/signature checker, which will happily
    check username/key against any proof signed by that user, which contains the user's
    username and UID.

## 0.0.15 (2014-03-29)

*SECURITY BUGFIXES*

  - Regression in last night's bugfix that let any proof go through in website proofs.

## 0.0.14 (2014-03-28)

Bugfixes:

  - Ignore DOS "\r"s in Website and Github proofs
  - Do a better "existing" check for Websites, which was broken.

## 0.0.13 (2014-03-27)

Bugfixes:

  - more case insensitivity

## 0.0.12 (2014-03-27)

Bugfixes:

  - Case-insensitive username checks

## 0.0.11 (2014-03-27)

Features:

  - Extra safety check for IDNs; if node's url module breaks, we'll throw an error
  - New 'resource_id()' for remote key proof objects.

## 0.0.10 (2014-03-26)

Features:

  - Prove you own a website

## 0.0.9 (2014-03-26)

Bugfixes:

  - Handle twitter usernames that are numbers

## 0.0.8 (2014-03-11)

Features:

  - Allow proxy'ing of scraper calls
  - Allow for ca's to be specified, useful when using a self-signed proxy above.

## 0.0.7 (2014-03-10)

Bugfixes:

 - Loosen up checking for twitter proofs, allow @-prefixing.
 - Better debug logging flexibility, and a cleanup

## 0.0.6 (2014-03-09)

Bugfixes:

 - Twitter proofs were broken, with hunt v hunt2

## 0.0.5

Features:

  - Add debugging for proofs that are inexplicably failing.
  - Inaugural changelog
