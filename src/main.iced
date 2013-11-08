
mods = [
  require('./web_service')
]

for m in mods
  for k,v of m
    exports[k] = v
