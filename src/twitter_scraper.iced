request   = require 'request'
cheerio   = require 'cheerio'
v_codes   = require('./constants').constants.v_codes

class TwitterScraper

  constructor: ->

  # ---------------------------------------------------------------------------

  hunt: (username, signature, cb) ->
    # calls back with err, tweet_id
    err      = null
    tweet_id = null

    await @_get_url_body "https://twitter.com/#{username}", defer err, html
    if err?
      res = v_codes.FAILED_LOAD
    else
      $ = cheerio.load html
      #
      # Only look inside the stream
      #
      stream = $('.profile-stream li.stream-item .tweet')
      if not stream.length
        err = v_codes.CONTENT_FAILURE
        # 
        # special case of no stream found 
        # - if their tweets are protected
        #
        if $('.stream-protected').length
          err = v_codes.NOT_PUBLIC
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
            if (p.first().html().indexOf signature) isnt -1
              tweet_id = item.data('tweetId')
              break
        if not tweet_id?
          err = v_codes.TEXT_NOT_FOUND

    cb err, tweet_id

  # ---------------------------------------------------------------------------

  check_status: (username, status_id, signature, cb) ->
    # calls back with a v_code or null if it was ok
    err = null
    await @_get_url_body "https://twitter.com/#{username}/status/#{status_id}", defer err, html
    if err?
      err = v_codes.FAILED_LOAD
    else
      $ = cheerio.load html
      #
      # only look inside the permalink tweet container
      # 
      div = $('.permalink-tweet-container .permalink-tweet')
      if not div.length
        err = v_codes.FAILED_PARSE
      else
        div = div.first()

        #
        # make sure both the username and tweet id match our query, 
        # in case twitter printed other tweets into the page
        # inside this container
        #
        if username.toLowerCase() isnt div.data('screenName')?.toLowerCase()
          err = v_codes.CONTENT_FAILURE
        else if status_id isnt div.data('tweetId')
          err = v_codes.CONTENT_FAILURE
        else

          #
          # finally look inside for the signaure in the tweet text
          #
          p = div.find('p.tweet-text')
          if not p.length
            err = v_codes.FAILED_PARSE
          else
            if (p.first().html().indexOf signature) is -1
              err = v_codes.TEXT_NOT_FOUND
    cb err

  # ---------------------------------------------------------------------------

  _get_url_body: (url, cb) ->
    ###
      cb(err, body) only replies with body if status is 200
    ###
    await request url, defer err, response, body
    if (not err) and (response.statusCode is 200)
      cb null, body
    else
      cb (response.statusCode or err), null


module.exports = TwitterScraper