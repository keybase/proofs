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

  _convert_url_to_mobile : (api_url) ->
    # The Facecbook desktop site stopped serving public post content to logged-out
    # requests starting sometime before 2019-09-17.

    # The Facebook mobile site does not enforce that the author username
    # matches the post ID being requested. For example these two urls will return
    # similar results.
    # https://m.facebook.com/mike.maxim/posts/10154017925505382
    # https://m.facebook.com/maxtaco/posts/10154017925505382
    # (The response is not determinsitic anyway)
    # So, the URL cannot be relied upon to enforce author username ownership.

    # We've waffled between desktop and mobile sites a few times, so rewrite
    # the URL for the current strategy which is to use the mobile site.
    mobile = "https://m.facebook.com/"
    desktop = "https://www.facebook.com/"
    if api_url.startsWith(desktop)
      # Only replace the first occurrence.
      return api_url.replace(desktop, mobile)
    else
      return api_url

  # ---------------------------------------------------------------------------

  _check_api_url : ({api_url, username}) ->
    if not api_url?
      return false

    # Note that the Facebook m-site does *not* enforce that the username in a
    # URL matches the author of the post. We can only rely on that as long as
    # we're using the desktop site.
    rxx = new RegExp("^https://m.facebook.com/#{username}/posts/[0-9]+$", "i")
    desktop_url = @_convert_url_to_mobile(api_url)
    return desktop_url.match(rxx)

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->
    # Facebook URLs contain more input from the user than other types (which
    # are purely built by the hunters), and so we need to fully validate them
    # here.
    
    # We cannot rely on the post URL to assert the author.
    # (Most people have a profile link in the desktop page that we could use
    # instead, but people with the "no scraping my profile" Facebook privacy
    # setting do *not*.)
    if not @_check_api_url({api_url, username})
      @log "Facebook post URL isn't valid for user #{username}: #{api_url}"
      return cb null, v_codes.CONTENT_FAILURE

    desktop_url = @_convert_url_to_mobile(api_url)

    # calls back with a v_code or null if it was ok
    await @_get_url_body { url: desktop_url }, defer err, rc, raw
    if err? or rc != v_codes.OK
      return cb err, rc

    page$ = @libs.cheerio.load(raw);

    # Check proofs in a way similar to the client, but not exactly the same.
    # Different for no reason other than the economy of time spent on this.

    post_text = page$('#m_story_permalink_view h3.by.bz').eq(0).contents().text()
    unless post_text
      return cb null, v_codes.CONTENT_FAILURE
    # Should be like: "Verifying myself: I am max on Keybase.io. 7UfLNPB0BcRS_YrSYbbePN4Zda-oX4Isd_pnOwS1JGU"
    unless proof_text_check is post_text
      return cb null, v_codes.CONTENT_FAILURE

    # Check the username in the href of the "Join" button under "Foo Barzum is on Facebook. To connect with Foo, join Facebook today."
    # Checking for the correct username is essential here. We rely on this
    # check to prove that the user in question actually wrote the post.
    join_href = page$('#mobile_login_bar div.u a').eq(0).attr('href')
    unless join_href
      return cb null, v_codes.CONTENT_FAILURE
    rxx = new RegExp "^/r\\.php\\?next=https.*facebook.com%2F([^/]*)%2Fposts.*$"
    unless (match = join_href.match rxx)?
      return cb null, v_codes.FAILED_PARSE
    username_from_join_href = match[1]
    if username_from_join_href != username
      return cb null, v_codes.CONTENT_FAILURE

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
