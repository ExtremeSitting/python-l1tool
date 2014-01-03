#!/usr/bin/env python

import re

class Sanitizer(object):
    """This will sanitize user input so things can't be backgrounded or
        sub-shelled. Pipe is allowed at this time. By providing additional
        args in the form of regex, you can further sanitize user input to
        only include certain things.
        Seperate bad chars with a pipe to define multipes"""

    def __init__(self):
        log_level = None
        log = None
        self.badchars = re.compile(r'(\s?[\)\(<>;&$`\]\[\}\{\|\\\n\r\t]+[\w\W]*)',
            re.IGNORECASE)

    def log_it(self):
        return self.log_level, self.log

    def _to_log(self, level, log):
        self.log_level = level
        self.log = log

    def sanitize(self, line, req=None, bad=None):
        if bad is None:
            bad = ''
        if req is None:
            req = '.+'
        if len(self.badchars.split(line)) > 1:
            self._to_log('warn' ,'Attempted Bad chars: %s' % line)
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

import paramiko

class Connect(object):

    def __init__(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self, server=None, key=None):
        if server or key is None:
            raise Exception('No server or Key')
        try:
            ssh.connect(server, username='root', key_filename=key)
            return ssh
        except paramiko.AuthenticationException:
            print 'Unable to login to remote host.'


