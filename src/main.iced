
mods = [
  require('./web_service')
  require('./b64extract')
  require('./util')
  require('./alloc')
  require('./alloc3')
  require('./constants')
  require('./base')
  require('./track')
  require('./auth')
  require('./update_passphrase_hash')
  require('./update_settings')
  require('./device')
  require('./revoke')
  require('./cryptocurrency')
  require('./per_user_key')
  require('./wallet')
  require('./subkey')
  require('./sibkey')
  require('./eldest')
  require('./pgp_update')
  require('./announcement')
  require('./scrapers/twitter')
  require('./scrapers/facebook')
  require('./scrapers/base')
  require('./scrapers/github')
  require('./scrapers/reddit')
  require('./scrapers/generic_web_site')
  require('./scrapers/dns')
  require('./scrapers/coinbase')
  require('./scrapers/hackernews')
  require('./scrapers/generic_social')
  require('./errors')
]

for m in mods
  for k,v of m
    exports[k] = v

# Leave it namespaced; don't poke into namespace for teams
exports.team = require('./team')
exports.team_hidden = require('./team_hidden')
exports.sig3 = require('./sig3')
