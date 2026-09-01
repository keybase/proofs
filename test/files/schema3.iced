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
