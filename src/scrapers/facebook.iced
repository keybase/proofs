{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants
{decode_sig} = require('kbpgp').ukm
{make_ids} = require '../base'

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

  _check_api_url : ({api_url,username}) ->
    # The Facebook mobile site (unlike the desktop site, weirdly) *ignores* the
    # username in a post URL. So asserting the username here does *not* prove
    # that this user authored the post. We still have to do that inside the
    # text.
    #
    # What we are checking here, is that the page we're loading is in fact a
    # post. If not, who knows what markup we could be tricked into matching.
    # It's hard to know for sure what tricks an attacker (probably the Keybase
    # server in this case) might be able to pull with all the different
    # Facebook endpoints that exist, so we're as strict with the URL here as we
    # can be. We enforce that post ID's are numeric-only, though we might need
    # to relax that if we find any exceptions.
    rxx = new RegExp("^https://m.facebook.com/#{username}/posts/[0-9]+$", "i")
    return (api_url? and api_url.match(rxx));

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, proof_text_check, remote_id}, cb) ->
    # calls back with a v_code or null if it was ok
    await @_get_url_body { url: api_url }, defer err, rc, raw
    if err? or rc != v_codes.OK
      return cb err, rc

    [rc, fb_username, fb_text] = @_extract_username_and_text raw
    if rc != v_codes.OK
      return cb null, rc

    if not usernames_equal(username, fb_username)
      @log "expected username '#{username}' but found '#{fb_username}'"
      return cb null, v_codes.BAD_USERNAME

    if proof_text_check.trim() != fb_text.trim()
      @log "expected proof '#{proof_text_check}' but found '#{fb_text}'"
      return cb null, v_codes.BAD_USERNAME

    cb null, v_codes.OK

  # ---------------------------------------------------------------------------

  _extract_username_and_text : (html) ->
    $ = @libs.cheerio.load html
    # Get the username from the first link in the first header in the story.
    user_profile_link = $('#m_story_permalink_view h3 a').first().attr('href')
    if not user_profile_link?
      @log "failed to find link to author profile"
      return [v_codes.CONTENT_MISSING, null, null]
    link_regex = new RegExp("^https://m.facebook.com/([a-zA-Z.]+)?", "i")
    match = user_profile_link.match(link_regex)
    if not match?
      @log "failed to parse author profile link"
      return [v_codes.CONTENT_MISSING, null, null]
    username = match[1]

    # Get the proof text from the contents of the second header in the story.
    proof_text = $('#m_story_permalink_view h3').eq(1).text()
    if not proof_text? or proof_text == ""
      @log "failed to find proof text"
      return [v_codes.CONTENT_MISSING, null, null]

    return [v_codes.OK, username, proof_text]

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

#================================================================================

username_normalize = (username) ->
  # Lowercase the letters and remove all dots.
  username.toLowerCase().replace(/\./g)

usernames_equal = (user1, user2) ->
  username_normalize(user1) == username_normalize(user2)
