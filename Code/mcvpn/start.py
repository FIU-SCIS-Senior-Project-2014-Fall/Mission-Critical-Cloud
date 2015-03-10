#!/usr/bin/env python

import argparse
import getpass
import hashlib
import json
import sys
import subprocess
import VirtualMachine
import XMPPServer
import openstack



CONFIG = {
    "username":"ipopuser",
    "hostname":"ejabberd",
    "group":"mcvpn",
    "password":"password",
    "host":"131.94.128.21"
}

'''
Requests VM list from Openstack using openstack.py functions

    @param self
    @return vms
'''
def vm_list():
    vms = openstack.list_vms()
    return vms


'''
Installs ejabberd and starts the service

'''
def _ejabberd_start(self):
    subprocess.Popen(["service", "ejabberd", "restart"])

def _install(self):
    subprocess.Popen(["apt-get", "update"])
    subprocess.Popen(["apt-get", "install", CONFIG["hostname"]])
    subprocess.Popen(["cp", "ejabberd.cfg", "/etc/ejabberd/"])
    self._start()
    subprocess.Popen(["ejabberdctl", "register", CONFIG["username"], CONFIG["hostname"], CONFIG["password"]])

    # Register all vms
    logging.debug("REGISTERING VIRTUAL MACHINES")
    vms = self.vm_list()
    for v in vms:
        subprocess.Popen(["ejabberdctl", "register", v, CONFIG["hostname"], CONFIG["password"])
        logging.debug("%s registered")

    # Add all nodes in demo group to each other
    subprocess.Popen(["ejabberdctl", "push_alltoall", CONFIG["hostname"], CONFIG["group"]])

    logging.debug("ALL VIRTUAL MACHINES REGIESTERD AND PUSHED ALL TO ALL")


def main(self):
    _install()
    _ejabberd_start()
    xmpp = XmppServer(host=CONFIG['host'], username=CONFIG['username'], \
        password=CONFIG['password'])
    logging.debug("XMPP SERVER STARTED "),
    logging.debug(xmpp)
