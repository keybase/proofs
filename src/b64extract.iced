
{bufeq_fast} = require('pgp-utils').util

#-----------------------------------------------------------------
#
# Given a block of unstructure text, extra the longest base64 blocks we can find.
# Return a list of them
#
exports.base64_extract = base64_extract= (text) ->
  # for either web64 or standard 64, here is our total alphabet
  b64x = /^[a-zA-Z0-9/+_-]+(=*)$/
  tokens = text.split /\s+/
  state = 0
  out = []
  curr = []

  hit_non_b64 = () ->
    if curr.length
      out.push(curr.join(''))
      curr = []
  hit_b64 = (tok) ->
    curr.push(tok)

  for tok in tokens
    if (tok.match b64x) then hit_b64(tok)
    else hit_non_b64()
  hit_non_b64()

  return out

#-----------------------------------------------------------------

class Finder

  constructor : (corpus) ->
    @rxx = new RegExp '^\\s*(([a-zA-Z0-9/+_-]+)(={0,3}))\\s*$'
    @lines = corpus.split /\r*\n/

  find_one_block : (start) ->
    found = false
    ln_out = start
    parts = []
    for line,i in @lines[start...]
      ln_out++
      if (m = line.match @rxx)?
        found = true
        parts.push m[1]
        if m[3].length > 0
          ln_out++
          break
      else if found
        break
    [(parts.join ""), ln_out]

  find : (needle) ->
    i = 0
    while i < @lines.length
      [msg, i] = @find_one_block i
      if msg.length
        buf = new Buffer msg, 'base64'
        return true if bufeq_fast buf, needle
    return false

#============================

# Given the unstructured string (haystack), find the buffer (need) byte-for-byte
# Return true if it's found, and false otherwise
exports.b64find = (haystack, needle) -> (new Finder haystack).find needle

#-----------------------------------------------------------------
