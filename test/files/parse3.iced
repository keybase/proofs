parse3 = require '../../lib/parse3'
schema = require '../../lib/schema3'

exports.hex_rejects_trailing_junk = (T, cb) ->
  uid = "00".repeat(15) + "19"
  hash = "00".repeat(32)

  uid_upper = "AA".repeat(15) + "19"

  T.assert parse3.is_hex(uid, 16), "valid uid hex is accepted"
  T.assert parse3.is_hex(uid_upper, 16), "uppercase uid hex is accepted"
  T.assert not parse3.is_hex(uid + "zz", 16), "uid hex plus junk is rejected"
  T.assert not parse3.is_hex(uid + "a", 16), "odd-length uid hex is rejected"
  T.assert not parse3.is_hex(hash + "nothex", 32), "hash hex plus junk is rejected"

  T.assert not parse3.is_uid(hash), "length has to match"

  err = schema.uid().convert().check uid
  T.assert not err?, "valid uid converts"

  err = schema.uid().convert().check uid_upper
  T.assert not err?, "uppercase uid converts"

  err = schema.uid().convert().check hash
  T.assert err?, "length has to match"

  err = schema.uid().convert().check uid + "zz"
  T.assert err?, "uid with trailing junk is rejected"

  err = schema.uid().convert().check uid + "a"
  T.assert err?, "odd-length uid is rejected"

  err = schema.hash().convert().check hash + "zz"
  T.assert err?, "hash with trailing junk is rejected"

  out = parse3.unhex uid
  T.assert Buffer.isBuffer(out) and out.length is 16, "unhex accepts valid uid"

  out = parse3.unhex uid_upper
  T.assert Buffer.isBuffer(out) and out.length is 16, "unhex accepts uppercase uid"

  for bad in [uid + "zz", uid + "a"]
    err = null
    try
      parse3.unhex bad
    catch e
      err = e
    T.assert err?, "unhex rejects #{bad}"
    T.assert err.toString().indexOf("bad binary or hex string") >= 0, "unhex error message"

  cb null

exports.hex_rejects_length_like_objects = (T, cb) ->
  uid_buf = Buffer.alloc 16
  T.assert parse3.is_hex(uid_buf, 16), "buffer of the right length is accepted"
  T.assert not parse3.is_hex(Buffer.alloc(15), 16), "buffer of the wrong length is rejected"
  T.assert not parse3.is_hex({length : 16}, 16), "plain object with length is rejected"
  T.assert not parse3.is_hex((0 for i in [0...16]), 16), "array of the right length is rejected"
  T.assert not parse3.is_uid({length : 16}), "is_uid rejects a length-like object"

  cb null
