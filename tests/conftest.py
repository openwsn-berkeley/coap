import os
import sys
here = sys.path[0]
sys.path.insert(0, os.path.join(here,))

print here

import logging
import logging.handlers

import pytest

import testUtils as utils

#============================ logging ===============================

log = logging.getLogger('conftest')
log.addHandler(utils.NullHandler())

#============================ defines ===============================

LOG_MODULES = [
    'conftest'
]

#============================ fixtures ==============================

#===== logFixture

def getTestModuleName(request):
    return request.module.__name__.split('.')[-1]

def getTestFunctionName(request):
    return request.function.__name__.split('.')[-1]

def loggingSetup(request):
    moduleName = getTestModuleName(request)
    
    # create logHandler
    logHandler = logging.handlers.RotatingFileHandler(
       filename    = '{0}.log'.format(moduleName),
       mode        = 'w',
       maxBytes    = 2000000,
       backupCount = 5,
    )
    logHandler.setFormatter(
        logging.Formatter(
            '%(asctime)s [%(name)s:%(levelname)s] %(message)s'
        )
    )
    
    # setup logging
    for loggerName in [moduleName]+LOG_MODULES:
        temp = logging.getLogger(loggerName)
        temp.setLevel(logging.DEBUG)
        temp.addHandler(logHandler)
    
    # log
    log.debug("\n\n---------- loggingSetup")

def loggingTeardown(request):
    moduleName = getTestModuleName(request)
    
    # log
    log.debug("\n\n---------- loggingTeardown")
    
    # teardown logging
    for loggerName in [moduleName]+LOG_MODULES:
        temp = logging.getLogger(loggerName)
        temp.handler = []

@pytest.fixture(scope='module')
def logFixtureModule(request):
    loggingSetup(request)
    f = lambda : loggingTeardown(request)
    request.addfinalizer(f)

@pytest.fixture(scope='function')
def logFixture(logFixtureModule,request):
    
    # log
    log.debug('\n\n---------- {0}'.format(getTestFunctionName(request)))
    
    return logFixtureModule