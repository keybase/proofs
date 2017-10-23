{make_errors} = require 'iced-error'

exports.errors = make_errors {
  CLOCK_SKEW : "critical clock skew detected"
  WRONG_SEQNO : "wrong seqno"
}
