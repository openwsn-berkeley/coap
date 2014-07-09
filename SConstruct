import os
import subprocess
import SCons

#============================ banner ==========================================

banner  = [""]
banner += [" ___                 _ _ _  ___  _ _ "]
banner += ["| . | ___  ___ ._ _ | | | |/ __>| \ |"]
banner += ["| | || . \/ ._>| ' || | | |\__ \|   |"]
banner += ["`___'|  _/\___.|_|_||__/_/ <___/|_\_|"]
banner += ["     |_|                  openwsn.org"]
banner += [""]

print '\n'.join(banner)

#============================ SCons environment ===============================

env = Environment(
    ENV       = {'PATH' : os.environ['PATH']},
)

#===== help text

Help('''
Usage:
    scons unittests
    scons functests
''')

def default(env,target,source): print SCons.Script.help_text
Default(env.Command('default', None, default))

#============================ SCons targets ===================================

#===== pylint_all

pylint_all = env.Command(
    'pylint_all.log', [],
    'pylint --output-format=parseable    coap > $TARGET.file',
)
env.AlwaysBuild(pylint_all)
env.Alias('pylint_all', pylint_all)

#===== pylint_error

pylint_error = env.Command(
    'pylint_error.log', [],
    'pylint --output-format=parseable -E coap > $TARGET.file',
)
env.AlwaysBuild(pylint_error)
env.Alias('pylint_error', pylint_error)

#===== unittests

unittests = env.Command(
    'test_report.xml', [],
    'py.test tests/unit/ --junitxml $TARGET.file',
)
env.AlwaysBuild(unittests)
env.Alias('unittests', unittests)

#===== functests

functests = env.Command(
    'test_report.xml', [],
    'py.test tests/func/ --junitxml $TARGET.file',
)
env.AlwaysBuild(functests)
env.Alias('functests', functests)

#===== alltests

alltests = env.Command(
    'test_report.xml', [],
    'py.test tests --junitxml $TARGET.file',
)
env.AlwaysBuild(alltests)
env.Alias('alltests', alltests)
