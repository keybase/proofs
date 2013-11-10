
web_service = require './web_service'

#=======================================================

get_klass = (type) ->
  err = klass = null
  klass = switch type
    when "web.twitter" then web_service.TwitterBinding
    else  
      err = new Error "Uknown proof class: #{type}"
      null
  [err, klass]

#=======================================================

alloc = (type, arg) ->
  ret = null
  [err, klass] = get_klass type
  if klass?
    ret = new klass arg
  [err, ret]

#=======================================================

exports.get_klass = get_klass
exports.alloc = alloc

#=======================================================

