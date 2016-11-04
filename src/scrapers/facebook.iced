{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{decode_sig} = require('kbpgp').ukm
{make_ids} = require '../base'
url = require 'url'

#================================================================================

exports.FacebookScraper = class FacebookScraper extends BaseScraper

  # We don't actually hunt for Facebook proofs. The hunt2 method is a no-op.
  # Instead, after the user posts a proof, Facebook gives them a redirect back
  # to our servers, and we learn the proof ID that way. The check_status method
  # does actually check the status though.

  constructor: (opts) ->
    super opts

  # ---------------------------------------------------------------------------

  _check_args : (args) ->
    if not(args.username?)
      new Error "Bad args to Facebook proof: no username given"
    else if not (args.name?) or (args.name isnt 'facebook')
      new Error "Bad args to Facebook proof: type is #{args.name}"
    else
      null

  # ---------------------------------------------------------------------------

  hunt2 : ({username, proof_text_check, name}, cb) ->
    err = new Error "hunt2 is a no-op for Facebook"
    cb err, {}

  # ---------------------------------------------------------------------------

  _convert_url_to_desktop : (api_url) ->
    # Previously the api_url referred to the Facebook m-site, but now we want
    # to check the desktop site (because it enforces author usernames better,
    # and we can't rely on them being present in the markup). This is a
    # temporary measure to allow new, correct clients to check proofs with the
    # old URLs. Eventually we can convert everything in our DB/scraper and get
    # rid of it.
    mobile = "https://m.facebook.com/"
    desktop = "https://www.facebook.com/"
    if api_url.startsWith(mobile)
      # Only replace the first occurrence.
      return api_url.replace(mobile, desktop)
    else
      return api_url

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url, username}) ->
    if not api_url?
      return false

    # Note that the Facebook m-site does *not* enforce that the username in a
    # URL matches the author of the post. We can only rely on that as long as
    # we're using the desktop site.
    rxx = new RegExp("^https://www.facebook.com/#{username}/posts/[0-9]+$", "i")
    desktop_url = @_convert_url_to_desktop(api_url)
    return desktop_url.match(rxx)

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->
    # Facebook URLs contain more input from the user than other types (which
    # are purely built by the hunters), and so we need to fully validate them
    # here. We also rely on them to assert the author.
    if not @_check_api_url({api_url, username})
      @log "Facebook post URL isn't valid for user #{username}: #{api_url}"
      return cb null, v_codes.CONTENT_FAILURE

    desktop_url = @_convert_url_to_desktop(api_url)

    # calls back with a v_code or null if it was ok
    await @_get_url_body { url: desktop_url }, defer err, rc, raw
    if err? or rc != v_codes.OK
      return cb err, rc

    # Previously we would parse markup to extract the username and proof text.
    # We had to switch to the desktop site to validate the usernames of people
    # with the "no search engine scraping" Facebook privacy setting turned on.
    # That in turn made it much harder to parse the markup we get, because what
    # we want comes down in an embedded comment. However, because the desktop
    # site (again, unlike the m-site) does not display comments or ads to
    # logged-out users, we can do a simple string match on the whole page to
    # find the proof text. It's possible there's some way I haven't thought of
    # for other users to inject strings somewhere in this page, and if so we'll
    # need to change it.

    # See http://stackoverflow.com/a/6969486
    regex_escaped_proof_text = proof_text_check.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, "\\$&")

    # We require a tiny bit of structure, which is that the proof must appear
    # as the exact contents of an <a> tag. Again, this is just a textual search
    # -- the <a> tag in question is actually expected to be in a comment.
    proof_text_regex = new RegExp("<a[^>]*>\\s*#{regex_escaped_proof_text}\\s*</a[^>]*>")

    if not raw.match(proof_text_regex)?
      @log "failed to find proof text '#{proof_text_check}' in Facebook response"
      return cb null, v_codes.TEXT_NOT_FOUND

    cb null, v_codes.OK

  # ---------------------------------------------------------------------------

  # Given a validated signature, check that the proof_text_check matches the sig.
  # TODO: Mostly copied from the Twitter implementation, with some slightly
  # different whitespace handling. Factor this out?
  _validate_text_check : ({signature, proof_text_check }) ->
    [err, msg] = decode_sig { armored: signature }
    if not err?
      {med_id} = make_ids msg.body
      if proof_text_check.split(/\s+/).indexOf(med_id)  < 0
        err = new Error "Cannot find #{med_id} in #{proof_text_check}"
    return err
