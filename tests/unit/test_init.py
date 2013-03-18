import logging
import testUtils as utils

#============================ logging ===============================

log = logging.getLogger(utils.getMyLoggerName())
log.addHandler(utils.NullHandler())

#============================ defines ===============================

#============================ fixtures ==============================

#============================ helpers ===============================

#============================ tests =================================

def test_import(logFixture):
    import sys
    log.debug(sys.path)
    import coap