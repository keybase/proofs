schema = require '../../lib/schema3'

exports.or_combinator = (T, cb) ->
  schm = schema.or([
    schema.dict({
      name : schema.string()
      username : schema.string()
    })
    schema.dict({
      protocol : schema.string()
      hostname : schema.string()
    })
  ])

  err = schm.check { name : "reddit", username : "alice" }
  T.assert not err?, "object matching first term is accepted"

  err = schm.check { protocol : "https:", hostname : "example.com" }
  T.assert not err?, "object matching second term is accepted"

  err = schm.check { invalid : 1, obj : 2 }
  T.assert err?, "object matching no term is rejected"
  T.equal err?.message, "At <top>: no structure worked"

  cb null

exports.required_null_rejected = (T, cb) ->
  for val in [null, undefined]
    err = schema.array(schema.obj()).check [val]
    T.assert err?, "array of obj() rejects null"
    T.equal err?.message, "At <top>.0: value cannot be null"

    err = schema.array(schema.string()).check [val]
    T.assert err?, "array of obj() rejects null"
    T.equal err?.message, "At <top>.0: value cannot be null"

    err = schema.struct([schema.obj()]).check [val]
    T.assert err?, "struct of obj() rejects null"
    T.equal err?.message, "At <top>.0: value cannot be null"

    err = schema.struct([schema.string()]).check [val]
    T.assert err?, "struct of obj() rejects null"
    T.equal err?.message, "At <top>.0: value cannot be null"

    err = schema.dict({ x : schema.obj() }).check { x : val }
    T.assert err?, "dict required obj() null is rejected"
    T.equal err?.message, "At <top>.x: value cannot be null"

    err = schema.dict({ x : schema.string() }).check { x : val }
    T.assert err?, "dict required string null is rejected"
    T.equal err?.message, "At <top>.x: value cannot be null"

    err = schema.dict({ x : schema.string().optional() }).check { x : val }
    T.assert not err?, "dict optional string null is accepted"

  cb null
