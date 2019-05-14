{make_errors} = require 'iced-error'

exports.errors = make_errors {
  CLOCK_SKEW : "critical clock skew detected"
  WRONG_SEQNO : "wrong seqno"
  BAD_HIGH_SKIP : "bad high skip"
  BAD_PREV : "bad prev pointer"
}

exports.errsan = errsan = (s) ->
  if typeof(s) is 'number' then return s
  if typeof(s) is 'boolean' then return s
  if not s? then return s
  if typeof(s) isnt 'string'
    s = s.toString()
  map = {
    "&" : "&amp;"
    "<" : "&lt;"
    ">" : "&gt;"
    '"' : "&quot;"
    "'" : "&#x27;"
    "/" : "&#x2F;"
  }
  re = new RegExp("[" + Object.keys(map) + "]", "g")
  s.replace re, (c) -> (map[c] or c)
