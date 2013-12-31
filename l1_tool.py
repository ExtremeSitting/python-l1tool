#!/usr/bin/env python
"""This tool is designed to provide secure 'shell' access to servers only
    accessed by through a bastion."""
#TODO: ! I think the script should login to the destination host on script start and
#server change. It could then grab the list of servers and save the compute node
#info for filtering. This would also test connection to the server and could log
#success!
import paramiko
import logging
import logging.handlers
import time
import cmd
import re
import os
#TODO: Need to add command decorators for sanitation instead of assigning sline


class Commands(cmd.Cmd):
    """Cmd provides the way to create a pseudo-shell environment. Any command
        must be first defined here."""

    def __init__(self):
        """Initialize some variables"""
        cmd.Cmd.__init__(self)
        self.server = ''
        self.username = os.getlogin()
        self.connection = ''
        self.log = self.logger()

    def logger(self):
        CMD_logger = logging.getLogger('CMDLogger')
        CMD_logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s %(message)s')
        handler = logging.handlers.SysLogHandler(address=('XXXXXXX', 514))
        handler.setFormatter(formatter)
        CMD_logger.addHandler(handler)
        return CMD_logger

    intro = '*' * 50 + '\n' + '*' + ' ' * 20 + 'L1 Tool' + ' ' * 21 + '*' + \
            '\n' + '*' * 50 + '\n' 
    doc_header = 'Commands:'
    undoc_header = 'Other:'

    def preloop(self):
        """This will prompt user for credentials.
            Eventually they will be used for LDAP auth.
            For now it will be for logging."""
        self.server = self.sanitize(raw_input('Server IP: '),
            '\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s?')
        while not self.server:
            self.server = self.sanitize(raw_input('Server IP: '),
                '\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s?')
        self.prompt = self.username + '@' + self.server + '>> '
        self.log.info(self.prompt + 'Login')

    def emptyline(self):
        """This prevents the previous command from being run again if the
            user hits 'enter' on an empty line"""
        print ''

    def postcmd(self, stop, line):
        """After the command is run make sure the SSH connection has
            been closed"""
        if self.connection:
            self.connection.close()
        return cmd.Cmd.postcmd(self, stop, line)

    def postloop(self):
        """Make sure the connection is closed again when the script is
            exiting."""
        self.log.info( self.prompt + 'Logout')
        if self.connection:
            self.connection.close()

    def connect(self):
        """Setting up the SSH connection."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                        'XXXXXXX', username='XXXXXXX',
                        key_filename='XXXXXXX')
        except paramiko.AuthenticationException:
            print 'Unable to login to remote host.'
        self.connection = ssh

    def sanitize(self, line, req='.+', bad=''):
        """This will sanitize user input so things can't be backgrounded or
            sub-shelled. Pipe is allowed at this time. By providing additional
            args in the form of regex, you can further sanitize user input to
            only include certain things.
            Seperate bad chars with a pipe to define multipes"""
        badchars = re.compile(r'(\s?[\)\(<>;&$`\]\[\}\{\|\\\n\r\t]+[\w\W]*)',
            re.IGNORECASE)
        if len(badchars.split(line)) > 1:
            self.log.warn(self.prompt + "Attempted Bad chars: " + line)
        reqchars =  re.match(r'(' + req + ')', badchars.split(line)[0])
        if reqchars:
            rmvbad = re.sub(r'(' + bad + ')', '', reqchars.group())
            if rmvbad is not None:
                return rmvbad
            else:
                return None
        else:
            return None

    def command(self, command):
        """It's easier to pass this function around than the exec_command"""
        stdin, stdout, stderr = self.connection.exec_command(command)
        error = stderr.readlines()
        if error:
            self.log.error(self.prompt + command)
            print 'ERROR:'
            for err in error:
                print err[:-1]
        self.log.info(self.prompt + command)
        for out in stdout.readlines():
            print out[:-1]
        if self.connection:
            self.connection.close()

    def multioutcommand(self, command, interval):
        """Same as the command method, but it supports multiple runs"""
        self.log.info(self.prompt + command)
        for i in range(interval):
            stdin, stdout, stderr = self.connection.exec_command(command)
            for err in stderr.readlines():
                print err[:-1]
            for out in stdout.readlines():
                print out[:-1]
            print ''
            time.sleep(1)
        self.connection.close()
#TODO: This is gonna be special and big. It's not going to work in dev the way it will in prod.
# Not to sure how to accomplish this yet. It may be the very last thing I do.
    def do_swappers(self, line):
        """swappers
            Print swap use for linux slices"""
        del line
        print 'No swapping script in dev yet. Sorry...'

# This is an example function to follow when adding new commands.
# The function name must start with 'do_' with no other special chars.
#
#    def do_example(self, line):
#        sline = self.sanitize(line, req='', bad='')
#        self.connect()
#        self.command(sline)

    def do_goto(self, line):
        """goto
            Change the target host. This will update your prompt so you know
            which host you're poking. Does not accept host names.
            goto <IP>"""
        sline = self.sanitize(line,
            req='\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s?')
        if not sline:
            print 'goto <IP>'
        else:
            self.server = sline
            self.prompt = self.username + '@' + self.server + '>> '
            self.log.info(self.prompt + 'Change server') 

    def do_date(self, line):
        """date
            Prints current server time."""
        del line
        self.connect()
        self.command('date')

    def do_grep(self, line):
        """grep
            grep [options] pattern /var/log/<file>
            Works the same as it does in a normal linux environment.
            --help will return help documentation from the host server."""
        sline = sanitize(line, req='\/var\/log\/', bad='\.\.\/|-R|-r|--mmap|-f')
        if not sline:
            print 'grep [options] pattern /var/log/<file>'
        else:
            self.connect()
            self.command('grep ' + sline)

    def do_uptime(self, line):
        """uptime
            Print the remote system's running time, users and load avgerage."""
        del line
        self.connect()
        self.command('uptime')

    def do_ps(self, line):
        """ps
            ps [options]
            ps with no options will run 'ps aux'
            Same as the ps command you know and love."""
        sline = self.sanitize(line)
        self.connect()
        if not sline:
            self.command('ps aux')
        else:
            self.command('ps ' + sline)

    def do_ifconfig(self, line):
        """ifconfig
            Print all interfaces on host. No args are supported. Sorry."""
        sline = self.sanitize(line, req='$eth[0-9]|$vif[0-9]+\.[01]')
        self.connect()
        if not sline:
            self.command('sudo /sbin/ifconfig')
        else:
            self.command('sudo /sbin/ifconfig ')

    def do_link(self, line):
        """link
            Prints link status for eth0 or eth1 plus some stats."""
        sline = self.sanitize(line, req='\s?eth[0-9]')
        self.connect()
        if sline:
            self.command('sudo /sbin/ethtool ' + sline)
        else:
            print 'link <eth[0-9]>'

    def do_iostat(self, line):
        """iostat
            List device usage by tapdisk/physical disk. Runs one time with no
            arguments. A single integer after the command will run the command
            that many times up to 100.
            iostat <single integer>"""
        sline = self.sanitize(line)
        if not sline:
            self.connect()
            self.command('iostat -xmd')
        else:
            try:
                if int(sline) <=1 or int(sline) > 100:
                    sline = 2
                self.connect()
                self.multioutcommand('iostat -xmd', int(sline))
            except ValueError:
                print 'iostat <single integer>'

    def do_top(self, line):
        """top
            Secure 'top'. This provides the top 20 high cpu processes. It will
            run 5 times in 1 second intervals."""
        del line
        self.connect()
        self.multioutcommand(
            'uptime && ps -eo pcpu,pid,user,args | sort -k 1 -r | head -20', 5)

    def do_free(self, line):
        """free
            Print memory statistics. '-s' and '-c' will be filtered from input.
            free [options]"""
        sline = self.sanitize(line, bad='-s|-c')
        self.connect()
        if not sline:
            self.command('free -m')
        else:
            self.command('free ' + sline)

    def do_xentop(self, line):
        """xentop
            Print out stats on VMs in a 'Running' power-state."""
        del line
        self.connect()
        self.command('sudo /usr/sbin/xentop -b -i1')
#TODO: Restrict users to /var/log/. Looks like a job for regex!
    def do_logs(self, line):
        """list
            lists log files in /var/log/"""
        sline = self.sanitize(line, bad='\.\.\/')
        self.connect()
        if sline:
            self.command('ls -l /var/log/' + sline)
        else:
            self.command('ls -l /var/log/')
#TODO: Restrict users to /var/log/!
    def do_tail(self, line):
        """tail
            Returns the last 50 lines of a file in /var/log/"""
        sline = self.sanitize(line, bad='\.\.\/')
        if not sline:
            print 'tail <file>'
        else:
            self.connect()
            self.command('sudo tail -50 /var/log/' + sline)

    def do_bwm(self, line):
        """bwm
            Prints all interfaces current through-put in Kb/s at 1 sec intervals
            5 times with no arguments. '-D' and '-F' will be filtered from input
            You can specify a interface with -I <interface>."""
        sline = self.sanitize(line, bad='-D|-F')
        self.connect()
        if not sline:
            self.multioutcommand('bwm-ng -c1 -o plain', 5)
        else:
            self.multioutcommand('bwm-ng -c1 -o plain ' + sline, 5)

    def do_packets(self, line):
        """packets
            Prints all interfaces current packet per second count at 1 sec
            intervals 5 times with no arguments. You can specify an interface
            with -I <interface>."""
        sline = self.sanitize(line)
        self.connect()
        if not sline:
            self.multioutcommand('bwm-ng -c1 -o plain -u packets', 5)
        else:
            self.multioutcommand('bwm-ng -c1 -o plain -u packets ' + sline, 5)
#TODO: Add usage documentation. TCPdump is a really powerful tool that could be malicious in a scripted format. May remove or only allow a few options!!!
    def do_tcpdump(self, line):
        """tcpdump
            Runs tcpdump on the remote host. For this to work quickly, there
            needs to be traffic. If the host is having network problems, you
            may find that this takes a long time to return output. However,
            normal traffic (mostly TCP) should come back relitively quickly.
            tcpdump -i <interface> """
        sline = self.sanitize(line)
        self.connect()
        if not sline:
            print 'Using interface 0...'
            self.command('sudo /usr/sbin/tcpdump -lU -c100 -nn -i eth0')
        else:
            self.command('sudo /usr/sbin/tcpdump -l -c100 -nn ' + sline)

    def do_list(self, line):
        """list
            List all VMs on the Hypervisor. xe vm-list options are supported.
            list <slice ID> [params=<param>]"""
        sline = self.sanitize(line, bad='Control\s[\w\s\W]+')
        self.connect()
        if not sline:
            self.command('sudo xe vm-list')
        else:
            self.command('sudo xe vm-list name-label=' + sline)

    def do_start(self, line):
        """start
            Start a VM
            start <slice####>"""
        sline = self.sanitize(line)
        self.connect()
        if not sline:
            print 'start <slice ID>'
        else:
            self.command('sudo xe vm-start name-label=' + sline)
#TODO: filter compute info so compute can't be rebooted!
    def do_reboot(self, line):
        """reboot
            Reboot a slice.
            reboot <slice####>"""
        sline = self.sanitize(line, bad='Control\s[\w\s\W]+')
        self.connect()
        if not sline:
            print 'reboot <slice ID>'
        else:
            self.command('sudo xe vm-reboot --force name-label=' + sline)

    def do_tasks(self, line):
        """tasks
            Print tasks returned by xe task-list."""
        del line
        self.connect()
        self.command('sudo xe task-list')

    def do_cancel(self, line):
        """cancel
            Cancel a pending task.
            cancel <task UUID>"""
        sline = self.sanitize(line)
        if not sline:
            print 'cancel <task UUID>'
        else:
            self.connect()
            self.command('sudo xe task-cancel uuid=' + sline)

    def do_disks(self, line):
        """disks
            List all vm disks. This will list every vdi and vbd for every slice.
            xe vm-disk-list options are supported.
            disks <slice ID> [params=<params>]"""
        sline = self.sanitize(line)
        self.connect()
        if not sline:
            self.command('sudo xe vm-disk-list --multiple')
        else:
            self.command('sudo xe vm-disk-list name-label=' + sline)

    def do_df(self, line):
        """df
            Print disk usage statistics."""
        sline = self.sanitize(line)
        self.connect()
        if not sline:
            self.command('df -h')
        else:
            self.command('df ' + sline)

    def do_exit(self, line):
        """exit
            Exit the tool cleanly."""
        del line
        return True

if __name__ == '__main__':
    try:
        Commands().cmdloop()
    except KeyboardInterrupt:
        print '^C'
