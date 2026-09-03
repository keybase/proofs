{alloc,get_klass} = require '../../'

exports.test_unknown_type = (T,cb) ->
  for type in ["", "not_a_real_type", "toString", "constructor", "__proto__"]
    [err, klass] = get_klass type
    T.assert err?, "error"
    T.equal err.message, "Unknown proof class: #{type}", "right message"
    T.assert not klass?, "no klass"
    T.assert not(alloc type, {}), "alloc returns null"

  cb null

exports.test_extra_lookup_tab = (T,cb) ->
  class Dummy
    constructor : (args) -> @args = args

  # only used in keybase-proofs-test
  extra_lookup_tab = {
    "test.web_service_binding.rooter" : Dummy
  }

  [err, klass] = get_klass "test.web_service_binding.rooter", extra_lookup_tab
  T.assert not err?, "no error for extra type"
  T.equal klass, Dummy, "extra type klass"
  obj = alloc "test.web_service_binding.rooter", {foo : 1}, extra_lookup_tab
  T.assert obj?, "alloc extra type"
  T.equal obj.args.foo, 1, "args passed through"

  [err, klass] = get_klass "track", extra_lookup_tab
  T.assert not err?, "builtin still found"
  T.assert klass?, "builtin klass"

  for type in ["", "not_a_real_type", "toString", "constructor", "__proto__"]
    [err, klass] = get_klass type, extra_lookup_tab
    T.assert err?, "error"
    T.equal err.message, "Unknown proof class: #{type}", "right message"
    T.assert not klass?, "no klass"
    T.assert not(alloc type, {}, extra_lookup_tab), "alloc returns null"

  cb null
