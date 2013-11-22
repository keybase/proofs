
mods = [
  require('./web_service')
  require('./util')
  require('./alloc')
  require('./constants')
]

for m in mods
  for k,v of m
    exports[k] = v
