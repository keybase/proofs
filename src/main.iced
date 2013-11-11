
mods = [
  require('./web_service')
  require('./util')
]

for m in mods
  for k,v of m
    exports[k] = v
