#!/usr/bin/env python

import argparse
import getpass
import hashlib
import json
import logging
import random
import select
import struct
import sys
import subprocess
import VirtualMachine
import xmpp_setup
import XMPPServer


# This dictionary contains a mapping of all of the current 
# virtual machines that are running in OpenStack

DEMO_GROUP = { 
    "jules":"password", 
    "claire":"password", 
    "saman":"password", 
    "ming":"password"
}

subprocess.Popen(["apt-get", "update"])
subprocess.Popen(["apt-get", "install", "ejabberd"])
subprocess.Popen(["cp", "ejabberd.cfg", "/etc/ejabberd/"])
subprocess.Popen(["service", "ejabberd", "restart"])
subprocess.Popen(["ejabberdctl", "register", "ipopuser", "ejabberd", "password"])

# Register all vms in demo group
for u,p in DEMO_GROUP:
    subprocess.Popen(["ejabberdctl", "register", u, "ejabberd", p])

# Add all nodes in demo group to each other
subprocess.Popen(["ejabberdctl", "push_alltoall", "ejabberd", "svpn"])

    
    