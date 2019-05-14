
{errsan} = require '../../lib/errors'

exports.errsan = (T,cb) ->
  cases = [
    [ "alice bob charlie" , "alice bob charlie" ]
    [10, 10]
    ["aabbccee1122", "aabbccee1122"]
    ['just hanging out <what> <happened> "here"', "just hanging out &lt;what&gt; &lt;happened&gt; &quot;here&quot;"]
  ]
  for [inp, outp] in cases
    T.equal errsan(inp), outp, "right input/output"
  cb null
