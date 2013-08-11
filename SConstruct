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
''')

def default(env,target,source): print SCons.Script.help_text
Default(env.Command('default', None, default))

#============================ SCons targets ===================================

#===== unittests

unittests = env.Command(
    'test_report.xml', [],
    'py.test tests/unit/ --junitxml $TARGET.file',
)
env.AlwaysBuild(unittests)
env.Alias('unittests', unittests)
