'''
This file starts the tincan and mccvpn_controlller on the vm
as daemons
'''

#!/usr/bin/env python

from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess

# default configuration values
CONFIG = {
    'stun': ['131.94.133.123:3478'],
    'turn': [],  # Contains dicts with 'server', 'user', 'pass' keys
    'xmpp_host': '131.94.133.123',
    'xmpp_username': 'dvpnuser@ejabberd',
    'xmpp_password': 'dvpnPasswd',   
    'localhost': '127.0.0.1',
    "localhost6": "::1",
    'rpc_port': 5800,
    'notifications_port': 5801,
    'ip4': '172.16.0.0',
    'nova_ip': '10.0.0.0',
    'ip4_mask': 24,
    'subnet_mask': 32,
    'ip6_prefix': '2000:0dbc:41f2:4a3c',
    'ip6_mask': 64,
    'uid_size': 40,
    'sec': True,
    'wait_time': 5,
    'buf_size': 4096,
    'controller_logging' : 'logging.DEBUG',
    'router_mode': False,
    'traffic_window_size': 5,
    'on-demand_connection': False,
    'on-demand_inactive_timeout': 30,
    'tincan_path': './ipop-tincan-x86_64',
    'tincan_logging': 0,
    'controller_path': './dvpn_controller.py'
}

class ServiceArgsParser(argparse.ArgumentParser):
    """
    Subclass of ArgumentParser that overrides the error method so that the help is displayed whenever an error occurs.
    """
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

class IpValidator(argparse.Action):
    """
    Custom action to validate an IP Address.
    """
    def __call__(self, parser, args, values, option_string=None):
        """
        Validates an IP Address entered by the user.
        
        :param parser: parser object that contains this action.
        :type parser: ArgumentParser
        :param args: namespace object that will be returned by parse_args()
        :type args: Namespace
        :param values: associated command-line arguments
        :type values: list with the types already enforced
        :param option_string: option string that was used to invoke this action. It will be absent if the action is associated with a positional argument.
        :type option_string: string or None
        """
        ip = values[0]
        parts = ip.split('.')
        if len(parts) != 4:
            parser.error("Wrong IP Address format.")
        for i in xrange(4):
            try:
                part = int(parts[i])
                if part < 0 or part > 255:
                     parser.error("IP Address octets must be entered as base-10 integers from 0 to 255.")
            except ValueError:
                parser.error("IP Address octets must be entered as base-10 integers from 0 to 255.")
        setattr(args, self.dest, values)

def _load_config():
    # Update configuration defaults with values present in the config file
    try:
        with open('config.json', mode='r') as f:
            loaded_config = json.load(f)
        CONFIG.update(loaded_config)
    except IOError or ValueError:
        print('Missing or empty conf.json file. A new one will be created.', file=sys.stdout)
    
def _write_config():
    with open('config.json', 'w') as f:
      f.write(json.dumps(CONFIG))
      
def _setup(args):
    """
    setup description
    :param args: namespace object returned by parse_args()
    :type args: Namespace
    :returns: a message indicating whether the command succeded 
    :rtype: string
    """
    _load_config()
    msg = ''
    try:
        if args.ip_address:
            CONFIG['ip4'] = args.ip_address[0]
            msg = msg + 'Using VPN IP %s\n' % args.ip_address[0]
        if args.xmpp_host:
            CONFIG['xmpp_host'] = args.xmpp_host[0] 
            msg = msg + 'Using XMPP server at %s\n' % args.xmpp_host[0]
        if args.xmpp_credentials:
            CONFIG['xmpp_username'] = args.xmpp_credentials[0] 
            CONFIG['xmpp_password'] = args.xmpp_credentials[1]
            msg = msg + 'Using XMPP credentials %s\n' % args.xmpp_credentials
        if args.nova_ip:
            CONFIG['nova_ip'] = args.nova_ip[0]
            msg = msg + 'Using Nova IP %s\n' % args.nova_ip
        if len(sys.argv) == 2:
            pprint(CONFIG)
            msg = '';
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    _write_config()
    return msg

def _join(args):
    _load_config()
    if CONFIG['xmpp_host'] == None or CONFIG['xmpp_username'] == None or CONFIG['xmpp_password'] == None:
        print('Missing XMPP host information or credentials.', file=sys.stderr)
        sys.exit(1)
    # spawn tincan
    try:
        tincan = subprocess.Popen(['zdaemon','-p', CONFIG['tincan_path'], '-d', '-s', 'tincan', 'start'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tincan_stdout, tincan_stderr = tincan.communicate()
        if len(tincan_stderr) > 0:
            raise Exception(tincan_stderr)
    except Exception as e:
        print('Error spawning IPOP-TinCan: %s' % e, file=sys.stderr)
        sys.exit(1)
    # spawn controller
    try:
        dvpnc = subprocess.Popen(['zdaemon','-p', CONFIG['controller_path'], '-d', '-s', 'controller', 'start'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        dvpnc_stdout, dvpnc_stderr = dvpnc.communicate()
        if len(dvpnc_stderr) > 0:
            raise Exception(dvpnc_stderr)
    except Exception as e:
        print('Error spawning controller: %s' % e, file=sys.stderr)
        sys.exit(1)
    return 'Successfully joined the VPN.'

def _leave(args):
    _load_config()
    # stop tincan
    try:
        tincan = subprocess.Popen(['zdaemon','-p', CONFIG['tincan_path'], '-s', 'tincan', 'stop'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tincan_stdout, tincan_stderr = tincan.communicate()
        if len(tincan_stderr) != 0:
            raise Exception(tincan_stderr)
        print('Stopped IPOP-TinCan')
    except Exception as e:
        print('Error stopping IPOP-TinCan: %s' % e, file=sys.stderr)
    # stop controller
    try:
        dvpnc = subprocess.Popen(['zdaemon','-p', CONFIG['controller_path'], '-s', 'controller', 'stop'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        dvpnc_stdout, dvpnc_stderr = dvpnc.communicate()
        if len(dvpnc_stderr) > 0:
            raise Exception(dvpnc_stderr)
        print('Stopped controller')
    except Exception as e:
        print('Error stopping controller: %s' % e, file=sys.stderr)
    return ''

def _get_status():
    _load_config()
    status = 'IPOP-TinCan: '
    try:
        p = subprocess.Popen(['zdaemon','-p', CONFIG['tincan_path'], '-s', 'tincan', 'status'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p_stdout, p_stderr = p.communicate()
        status += 'Running'
    except OSError as e:
        status += 'Not running'
    status += '\nController: '
    try:
        p = subprocess.Popen(['zdaemon','-p', CONFIG['controller_path'], '-d', '-s', 'controller', 'status'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p_stdout, p_stderr = p.communicate()
        status += 'Running'
    except OSError as e:
        status += 'Not running'
    return status

def _status(args):
    return _get_status()
    
def main():
    #main parser
    parser = ServiceArgsParser(prog='dvpn-tool',
                               description='Command-line interface to manage DefenseVPN.',
                               epilog='See "dvpn-tool SUBCOMMAND -h" for help on a specific subcommand.')
    subparsers = parser.add_subparsers(title='positional arguments', 
                                       metavar='<subcommand>')
    #parser for 'setup'
    setup_parser = subparsers.add_parser('setup', 
                                          help='Enter P2P VPN IP Address and XMPP information. If no option is given, displays the current setup.',
                                          description='Creates a configuration file using default values or updates an existing one with the given values. \
                                          To create a new default configuration, call the setup option without arguments.',
                                          epilog='')
    setup_parser.add_argument('-a', '--ip_address',
                              nargs=1,
                              metavar=('IP'), 
                              default='',
                              action=IpValidator, 
                              help='IPv4 Address this machine will have within the P2P VPN. This should typically be in range reserved for communication within a private network as specified by RFC 1918.')
    setup_parser.add_argument('-x', '--xmpp_host',
                              nargs=1, 
                              metavar=('XMPP'),
                              default='', 
                              help='IP Address of the XMPP server.')
    setup_parser.add_argument('-c', '--xmpp_credentials',
                              nargs=2, 
                              metavar=('UID', 'PASSWD'),
                              default=[], 
                              help='User name and password used to log in to the XMPP server.')
    setup_parser.add_argument('-n', '--nova_ip',
                              nargs=1, 
                              metavar=('NOVAIP'),
                              default='', 
                              help='IP Address of the machine.')
    setup_parser.set_defaults(func=_setup)
    
    #parser for 'join'
    join_parser = subparsers.add_parser('join', 
                                         help='Join this node to the P2P VPN.',
                                         description='Starts IPOP-TinCan and the DefenseVPN controller using the parameters set in the configuration file.')
    join_parser.set_defaults(func=_join)
    
    #parser for 'leave'
    leave_parser = subparsers.add_parser('leave',
                                         help='Leave the P2P VPN.',
                                         description='Stops IPOP-TinCan and the DefenseVPN controller, removing this node from the VPN.')
    leave_parser.set_defaults(func=_leave)
    
    #parser for 'status'
    status_parser = subparsers.add_parser('status', 
                                          help='Display the status of the P2P VPN.', 
                                          description='Displays the status of the two pieces that provide the P2P VPN: IPOP-TinCan and the DefenseVPN Controller.')
    status_parser.set_defaults(func=_status)

    '''
    #parser for the 'restart' command
    parser_restart = subparsers.add_parser('restart', help='Restart the service. (Admin only)', description='Restart the Dynamic VM Migration Service.')
    parser_restart.set_defaults(func=_restart)
    '''
    args = parser.parse_args()
    print(args.func(args), file=sys.stdout)
    sys.exit(0)
    
if __name__ == '__main__':
    main()