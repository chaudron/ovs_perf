#  Copyright 2017 "OVS Performance" Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Files name:
#    dut_ssh_shell.py
#
#  Description:
#    Simple DUT SSH shell class
#
#  Author:
#    Eelco Chaudron
#
#  Initial Created:
#    17 January 2017
#

#
# Imports
#
import logging
import shlex
import spur
import sys

from spur import SshShell


#
# DutExecutionResult(object)
#
class DutExecutionResult(object):
    def __init__(self, return_code, stdout_output, stderr_output):
        self.return_code = return_code
        self.stdout_output = stdout_output.decode("utf-8", "ignore")
        self.stderr_output = stderr_output.decode("utf-8", "ignore")

    @property
    def output(self):
        return self.stdout_output + self.stderr_output


#
# DutSshShell(SshShell)
#
class DutSshShell(SshShell):
    def dut_exec(self, cmd, **kwargs):
        die_on_error = kwargs.pop("die_on_error", False)

        if 'raw_cmd' in kwargs:
            command = kwargs['raw_cmd']
        else:
            command = shlex.split(cmd)

        self.logger.debug("EXEC_I: \"{}\"".format(cmd))
        self.logger.debug("EXEC_F: \"{}\"".format(command))

        try:
            result = self.run(command, allow_error=True)
            result = DutExecutionResult(result.return_code,
                                        result.output,
                                        result.stderr_output)

        except spur.errors.NoSuchCommandError as e:
            result = DutExecutionResult(-100, "", e.message)
            pass

        self.logger.debug("RETURN: {}".format(result.return_code))
        self.logger.debug("STDOUT: >>{}<<END".format(
            result.stdout_output.encode('utf-8')))
        self.logger.debug("STDERR: >>{}<<END".format(
            result.stderr_output.encode('utf-8')))

        if result.return_code != 0 and die_on_error == True:
            print(("ERROR[%d]: Failed executing command, \"%s\", on DUT \"%s\""
                   % (result.return_code, " ".join(command), self._hostname)))
            sys.exit(-1)

        return result

    @property
    def logger(self):
        name = '.'.join(['dutSh', self._hostname])
        return logging.getLogger(name)
