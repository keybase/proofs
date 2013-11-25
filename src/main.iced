
mods = [
  require('./web_service')
  require('./util')
  require('./alloc')
  require('./constants')
  require('./base')
]

for m in mods
  for k,v of m
    exports[k] = v
