ICED=node_modules/.bin/iced
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp
UGLIFYJS=node_modules/.bin/uglifyjs
WD=`pwd`
BROWSERIFY=node_modules/.bin/browserify

default: build
all: build

lib/%.js: src/%.iced
	$(ICED) -I browserify -c -o `dirname $@` $<

$(BUILD_STAMP): \
	lib/alloc.js \
	lib/alloc3.js \
	lib/announcement.js \
	lib/auth.js \
	lib/base.js \
	lib/b64extract.js \
	lib/constants.js \
	lib/cryptocurrency.js \
	lib/device.js \
	lib/eldest.js \
	lib/errors.js \
	lib/main.js \
	lib/parse3.js \
	lib/revoke.js \
	lib/sibkey.js \
	lib/sig3.js \
	lib/subkey.js \
	lib/per_user_key.js \
	lib/pgp_update.js \
	lib/scrapers/base.js \
	lib/scrapers/bitbucket.js \
	lib/scrapers/coinbase.js \
	lib/scrapers/dns.js \
	lib/scrapers/facebook.js \
	lib/scrapers/generic_web_site.js \
	lib/scrapers/github.js \
	lib/scrapers/hackernews.js \
	lib/scrapers/reddit.js \
	lib/scrapers/twitter.js \
	lib/scrapers/generic_social.js \
	lib/team.js \
	lib/team_hidden.js \
	lib/track.js \
	lib/wallet.js \
	lib/web_service.js \
	lib/update_passphrase_hash.js \
	lib/update_settings.js \
	lib/util.js
	date > $@

build: $(BUILD_STAMP)

test-server: $(BUILD_STAMP)
	$(ICED) test/run.iced

test: test-server

clean:
	rm -rf lib/* lib/scrapers/* $(BUILD_STAMP) $(TEST_STAMP)

setup:
	npm install -d

.PHONY: clean setup test  test-browser
