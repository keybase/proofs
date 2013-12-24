{BaseScraper} = require './base'
{constants} = require '../constants'
{v_codes} = constants

#================================================================================

exports.TwitterScraper = class TwitterScraper extends BaseScraper

  constructor: ({libs}) ->
    super { libs }

  # ---------------------------------------------------------------------------

  hunt: (username, signature, cb) ->
    # calls back with err, out
    out      = {}
    rc       = v_codes.OK

    await @_get_url_body "https://twitter.com/#{username}", defer err, rc, html
    if rc is v_codes.OK

      $ = @libs.cheerio.load html

      #
      # Only look inside the stream
      #
      stream = $('.profile-stream li.stream-item .tweet')
      if not stream.length
        rc = v_codes.CONTENT_FAILURE
        # 
        # special case of no stream found 
        # - if their tweets are protected
        #
        if $('.stream-protected').length
          rc = v_codes.PERMISSION_DENIED
      else
        #
        # find the first tweet in the stream
        # that's definitely by them and containing
        # the signature
        #
        rc = v_codes.NOT_FOUND
        for stream_item in stream
          item = $(stream_item)
          if (item.data('screenName')?.toLowerCase() is username.toLowerCase()) and item.data('tweetId')?
            p = item.find 'p.tweet-text'
            if (p.first().html().indexOf signature) is 0
              rc = v_codes.OK
              remote_id = item.data('tweetId')
              api_url = human_url = @_id_to_url username, remote_id
              out = { remote_id, api_url, human_url }
              break
    out.rc = rc
    cb err, out

  # ---------------------------------------------------------------------------

  _id_to_url : (username, status_id) ->
    "https://twitter.com/#{username}/status/#{status_id}"

  # ---------------------------------------------------------------------------

  check_url : ({url,username}) ->
    return (url.indexOf("https://twitter.com/#{username}/") is 0)

  # ---------------------------------------------------------------------------

  check_status: ({username, api_url, signature, remote_id}, cb) ->
    # calls back with a v_code or null if it was ok
    await @_get_url_body api_url, defer err, rc, html

    if rc is v_codes.OK

      $ = @libs.cheerio.load html
      #
      # only look inside the permalink tweet container
      # 
      div = $('.permalink-tweet-container .permalink-tweet')
      if not div.length
        rc = v_codes.FAILED_PARSE
      else
        div = div.first()

        #
        # make sure both the username and tweet id match our query, 
        # in case twitter printed other tweets into the page
        # inside this container
        #
        rc = if (username.toLowerCase() isnt div.data('screenName')?.toLowerCase()) then v_codes.BAD_USERNAME
        else if (remote_id isnt div.data('tweetId')) then v_codes.BAD_REMOTE_ID
        else if not (p = div.find('p.tweet-text'))? or not p.length then v_codes.MISSING
        else if (p.first().html().indexOf signature) is 0 then v_codes.OK
        else v_codes.DELETED

    cb err, rc

  # ---------------------------------------------------------------------------

  _get_url_body: (url, cb) ->
    ###
      cb(err, body) only replies with body if status is 200
    ###
    body = null
    await @libs.request url, defer err, response, body
    rc = if err? then v_codes.HOST_UNREACHABLE
    else if (response.statusCode is 200) then v_codes.OK
    else if (response.statusCode >= 500) then v_codes.HTTP_500
    else if (response.statusCode >= 400) then v_codes.HTTP_400
    else if (response.statusCode >= 300) then v_codes.HTTP_300
    else                                      v_codes.HTTP_OTHER
    cb err, rc, body

#================================================================================

