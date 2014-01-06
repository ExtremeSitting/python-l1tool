#!/usr/bin/env python

import logging
import logging.handlers

class Logging(object):

    def __init__(self):
        pass

    def logger(self):
        CMD_logger = logging.getLogger('CMDLogger')
        CMD_logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s %(message)s')
        handler = logging.handlers.SysLogHandler(address=('localhost', 514),
                facility='local4')
        handler.setFormatter(formatter)
        CMD_logger.addHandler(handler)
        return CMD_logger

import re

class Sanitizer(object):
    """This will sanitize user input so things can't be backgrounded or
        sub-shelled. Pipe is allowed at this time. By providing additional
        args in the form of regex, you can further sanitize user input to
        only include certain things.
        Seperate bad chars with a pipe to define multipes"""

    def __init__(self):
        self.badchars = re.compile(r'(\s?[\)\(<>;&$`\]\[\}\{\|\\\n\r\t]+[\w\W]*)',
            re.IGNORECASE)
        self.log = Logging().logger()

    def sanitize(self, line, req=None, bad=None):
        if bad is None:
            bad = ''
        if req is None:
            req = '.+'
        if len(self.badchars.split(line)) > 1:
            self.log.warn('Attempted Bad chars: %s' % line)
            return None
        reqchars =  re.match(r'(' + req + ')', self.badchars.split(line)[0])
        if reqchars:
            rmvbad = re.sub(r'(' + bad + ')', '', reqchars.group())
            if rmvbad is not None:
                return rmvbad
            else:
                return None
        else:
            return None

import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import paramiko

class Connect(object):

    def __init__(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self, server=None, key=None):
        if server is None:
            raise Exception('No server')
        elif key is None:
            raise Exception('No key')
        try:
            self.ssh.connect(server, username='root', key_filename=key)
            return self.ssh
        except paramiko.AuthenticationException:
            print 'Unable to login to remote host.'


