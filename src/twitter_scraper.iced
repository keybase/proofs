request   = require 'request'
cheerio   = require 'cheerio'
v_codes   = require('./constants').constants.v_codes

#================================================================================

class TwitterScraper

  constructor: ->

  # ---------------------------------------------------------------------------

  hunt: (username, signature, cb) ->
    # calls back with rc, tweet_id
    rc       = v_codes.OK
    tweet_id = null

    await @_get_url_body "https://twitter.com/#{username}", defer err, rc, html
    if rc is v_codes.OK

      $ = cheerio.load html
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
        for stream_item in stream
          item = $(stream_item)
          if (item.data('screenName')?.toLowerCase() is username.toLowerCase()) and item.data('tweetId')?
            p = item.find 'p.tweet-text'
            if (p.first().html().indexOf signature) is 0
              tweet_id = item.data('tweetId')
              rc = v_codes.OK
              break
        if not tweet_id?
          rc = v_codes.NOT_FOUND

    cb err, rc, tweet_id

  # ---------------------------------------------------------------------------

  id_to_url : (username, status_id) ->
    "https://twitter.com/#{username}/status/#{status_id}"

  # ---------------------------------------------------------------------------

  check_status: (username, url, signature, cb) ->
    # calls back with a v_code or null if it was ok
    await @_get_url_body url, defer err, rc, html

    if rc is v_codes.OK

      $ = cheerio.load html
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
        rc = if (username.toLowerCase() isnt div.data('screenName')?.toLowerCase()) then v_codes.CONTENT_FAILURE
        else if (status_id isnt div.data('tweetId')) then v_codes.CONTENT_FAILURE
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
    await request url, defer err, response, body
    rc = if err? then v_codes.HOST_UNREACHABLE
    else if (response.statusCode is 200) then v_codes.OK
    else if (response.statusCode >= 500) then v_codes.HTTP_500
    else if (response.statusCode >= 400) then v_codes.HTTP_400
    else if (response.statusCode >= 300) then v_codes.HTTP_300
    else                                      v_codes.HTTP_OTHER
    cb err, rc, body

#================================================================================

module.exports = TwitterScraper