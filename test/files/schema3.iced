schema = require '../../lib/schema3'
{pack,unpack} = require 'purepack'

# These collide with Object.prototype and with lookups like obj[k] /
# obj.hasOwnProperty(k).
_object_proto_names = [
  "__proto__"
  "constructor"
  "hasOwnProperty"
  "isPrototypeOf"
  "propertyIsEnumerable"
  "toLocaleString"
  "toString"
  "valueOf"
]
# "Weird key names" - Object prototype keys but handled by schema3 library.
# With the exception of __proto__ - this one is banned because it requires
# extra care to get right and has more footguns. See src/schema3.iced
# is_reserved_key_name
_weird_key_names = (n for n in _object_proto_names when n isnt "__proto__")

exports.prototype_pollution_json = (T, cb) ->
  # parsing "__proto__" property should not change resulting object's
  # prototype.
  obj = JSON.parse('{"__proto__":1}')
  T.assert Object.getPrototypeOf(obj) is Object.prototype, "is Object.prototype"
  T.assert Object::hasOwnProperty.call(obj, '__proto__'), "hasOwnProperty __proto__"

  cb null

exports.prototype_pollution_purepack = (T, cb) ->
  # purepack does not allow __proto__ keys, although accidentially.

  # Create a purepack with aaaaaaaaa property
  aaa = Buffer.from (pack { aaaaaaaaa : 1 })

  # Sanity check, 'aaaaaaaaa' is just a normal key in an unpacked object.
  obj = unpack aaa
  T.assert Object.getPrototypeOf(obj) is Object.prototype, "is Object.prototype"
  T.assert Object::hasOwnProperty.call(obj, 'aaaaaaaaa'), "hasOwnProperty aaaaaaaaa"

  # Str-replace aaaaaaaaa into __proto__
  bin = Buffer.from(aaa.toString('binary').replace('aaaaaaaaa', '__proto__'), 'binary')
  err = null
  try
    unpack(bin)
  catch e
    err = e
  T.assert err?
  T.equal err?.message, "duplicate key '__proto__'"

  cb null

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

exports.dict_missing_mandatory_key = (T, cb) ->
  schm = schema.dict({
    n : schema.string().name("name")
    nick : schema.string().optional()
  })

  err = schm.check { n : "alice" }
  T.assert not err?, "optional key may be omitted"

  err = schm.check { nick : "a" }
  T.assert err?, "missing mandatory key is rejected"
  T.equal err?.message, "At <top>.n: key is missing but is mandatory"

  err = schm.check {}
  T.assert err?, "empty dict missing mandatory key is rejected"
  T.equal err?.message, "At <top>.n: key is missing but is mandatory"

  localized = schm.debug_localize { n : "alice" }
  T.equal localized.name, "alice", "debug_localize uses schema names"
  T.assert not localized.n?, "short key is replaced"

  cb null

exports.string_enum_rejects_unknown_weird_names = (T, cb) ->
  schm = schema.string_enum ["in_person", "proofs", "video"]
  err = schm.check "video"
  T.assert not err?, "listed enum value is accepted"

  err = schm.check "nope"
  T.assert err?, "unknown enum value is rejected"

  # Make sure that Object prototype names are not bugging out with string enum check.
  for name in _object_proto_names
    err = schm.check name
    T.assert err?, "#{name} is not an enum value just because it is a prototype name"
    T.assert (err?.message.indexOf("unknown enum value") >= 0), "#{name} error message"

  cb null

exports.string_enum_allows_weird_names = (T, cb) ->
  for name in _weird_key_names
    # Allow a string enum with weird name.
    schm = schema.string_enum [name]
    # And it can also be checked properly
    err = schm.check name
    T.assert not err?, "#{name} can be an enum value"
    err = schm.check "nope"
    T.assert err?, "other values still rejected next to #{name}"

  # Do not allow banned __proto__ name.
  threw = null
  try
    schema.string_enum ["__proto__"]
  catch e
    threw = e
  T.assert threw?, "__proto__ is not a valid enum value"
  T.equal threw?.message, "enum value is not allowed: __proto__"

  cb null

exports.dict_rejects_unknown_weird_keys = (T, cb) ->
  schm = schema.dict { name : schema.string() }
  err = schm.check { name : "ok" }
  T.assert not err?, "valid dict is accepted"

  err = schm.check { name : "ok", extra : 1 }
  T.assert err?, "unknown key is rejected"
  T.equal err?.message, "At <top>.extra: key is not supported"

  # Allow weird key names to be checked against the schema, they are just not
  # defined as dict fields and payloads with these fields are correctly
  # rejected. They are not rejected / banned, and are treated as any other name
  # (also see next test).
  for name in _weird_key_names
    obj = JSON.parse "{\"name\":\"ok\",\"#{name}\":1}"
    err = null
    threw = null
    try
      err = schm.check obj
    catch e
      threw = e
    T.assert not threw?, "#{name} should not throw"
    T.assert err?, "#{name} extra key is not a schema field"
    T.equal err?.message, "At <top>.#{name}: key is not supported"

  obj = JSON.parse '{"name":"ok","__proto__":1}'
  err = schm.check obj
  T.assert err?, "__proto__ extra key is rejected"
  T.equal err?.message, "At <top>.__proto__: key name is not allowed"

  schm = schema.dict({ name : schema.string() }).allow_extra_keys()
  obj = JSON.parse '{"name":"ok","constructor":1}'
  err = schm.check obj
  T.assert not err?, "constructor extra key is allowed when extra keys are allowed"

  obj = JSON.parse '{"name":"ok","__proto__":1}'
  err = schm.check obj
  T.assert err?, "__proto__ is rejected even with allow_extra_keys"
  T.equal err?.message, "At <top>.__proto__: key name is not allowed"

  cb null

exports.dict_weird_schema_keys = (T, cb) ->
  # Weird keys can be used in the schema as well, and objects with these
  # keys can be checked against the schemas.
  for name in _weird_key_names
    keys = {}
    keys[name] = schema.string()
    schm = schema.dict keys

    own = JSON.parse "{\"#{name}\":\"ok\"}"
    err = schm.check own
    T.assert not err?, "own #{name} key is accepted"

    err = schm.check {}
    T.assert err?, "inherited #{name} does not satisfy a required schema key"
    T.equal err?.message, "At <top>.#{name}: key is missing but is mandatory"

    localized = schm.debug_localize {}
    T.assert not Object::hasOwnProperty.call(localized, name), "debug_localize ignores inherited #{name}"
    localized = schm.debug_localize own
    T.equal localized[name], "ok", "own #{name} key is localized"

    schm = schema.dict { name : schema.string() }
    schm.set_key name, schema.string()
    obj = JSON.parse "{\"name\":\"ok\",\"#{name}\":\"ok\"}"
    err = schm.check obj
    T.assert not err?, "set_key can install #{name}"

  # With the exception of __proto__ which is rejected in the schema construction stage.
  keys = {}
  Object.defineProperty keys, "__proto__", { value : schema.string(), enumerable : true }
  threw = null
  try
    schema.dict keys
  catch e
    threw = e
  T.assert threw?, "__proto__ is not a valid schema key"
  T.equal threw?.message, "schema key name is not allowed: __proto__"

  schm = schema.dict { name : schema.string() }
  threw = null
  try
    schm.set_key "__proto__", schema.string()
  catch e
    threw = e
  T.assert threw?, "set_key rejects __proto__"
  T.equal threw?.message, "schema key name is not allowed: __proto__"

  cb null
