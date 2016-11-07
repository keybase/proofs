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
    # here. Also just as important, we rely on the post URL to assert the
    # author. (Most people have a profile link in the page that we could use
    # instead, but people with the "no scraping my profile" Facebook privacy
    # setting do *not*.)
    if not @_check_api_url({api_url, username})
      @log "Facebook post URL isn't valid for user #{username}: #{api_url}"
      return cb null, v_codes.CONTENT_FAILURE

    desktop_url = @_convert_url_to_desktop(api_url)

    # calls back with a v_code or null if it was ok
    await @_get_url_body { url: desktop_url }, defer err, rc, raw
    if err? or rc != v_codes.OK
      return cb err, rc

    page$ = @libs.cheerio.load(raw);
    # Get the contents of the first (only) comment inside the first <code>
    # block. Believe it or not, this comment contains the post markup below.
    first_code_comment = page$('code').eq(0).contents().toArray()[0]?.data
    if not first_code_comment?
      @log "failed to find proof markup comment in Facebook response"
      return cb null, v_codes.TEXT_NOT_FOUND
    # Facebook escapes "--" as "-\-\" and "\" as "\\" when inserting text into
    # comments. Unescape these. (Use split-join instead of replace to get all
    # occurrences without worrying about regex metacharacters.)
    unescaped_comment = first_code_comment.split("-\\-\\").join("--").split("\\\\").join("\\")
    # Re-parse the result as more HTML. This is the markup for the proof post.
    proof$ = @libs.cheerio.load(unescaped_comment)
    # This is the selector for the post attachment link. It's the "text of the
    # first <a> tag inside the div that's the immediate *sibling* of the
    # 'userContet' div".
    link_text = proof$('div.userContent+div a').text()

    if link_text.trim() != proof_text_check.trim()
      @log "failed to find attachment title '#{proof_text_check}' in Facebook post #{desktop_url}"
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
