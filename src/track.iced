
kbpgp = require 'kbpgp'
{Base} = require './base'
{constants} = require './constants'
{bufeq_secure,unix_time} = kbpgp.util

#==========================================================================

class TrackerProof extends Base

  constructor : ({km, @seqno, @user, @host}) ->


#==========================================================================
