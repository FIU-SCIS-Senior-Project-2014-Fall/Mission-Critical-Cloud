#!/usr/bin/env python
from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess
import uuid

# Installs and sets up ejabberd XMPP service on dedicated server
# Note: this can be one of your virtual machines. however best 
# performance is achieved if this is run on a separate server
# or the virtual machine host.

install =	{
		"ejabberd":
			[
			"sudo apt-get update", "sudo apt-get install ejabberd", 
			"cd ~", 
			"git clone git://github.com/processone/ejabberd-contrib.git",
			"cd ejabberd-contrib/mod_admin_extra",
			"git checkout 2.1.11",
			"./build.sh",
			"sudo cp ./ebin/mod_admin_extra.beam /usr/lib/ejabberd/ebin/",
			"sudo cp ./ejabberd.cfg /etc/ejabberd/"
			],
		
		"ejabberd_init":
			[
			"sudo ejabberdctl register namenode1 ejabberd password",
			"sudo ejabberdctl register namenode2 ejabberd password",
			"sudo ejabberdctl register datanode1 ejabberd password",		
			"sudo ejabberdctl register datanode2 ejabberd password",
			"sudo ejabberdctl register datanode3 ejabberd password",
			"sudo ejabberdctl register datanode4 ejabberd password",
			"sudo ejabberdctl register datanode5 ejabberd password",
			"sudo ejabberdctl register datanode6 ejabberd password",
			"sudo ejabberdctl register datanode7 ejabberd password",
			"sudo ejabberdctl register datanode8 ejabberd password",
			"sudo ejabberdctl push_alltoall ejabberd mcc"
			],
		"mcc":
			[
			"cd ~",
			"git clone https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git",
			"sudo cp ~/Mission-Critical-Cloud/Code/mcvpn/rejoin-openstack.conf /etc/init/"
			]
		}


def _run_cmd(s):
	for cmd in install[s]:
		print("Running " + "'"+cmd+"'")
		try: 
			subprocess.check_call(cmd.split(), stderr=subprocess.STDOUT)
		except(subprocess.CalledProcessError):
			continue

def main():	
	_run_cmd("mcc")
	_run_cmd("ejabberd")
	_run_cmd("ejabberd_init")    

if __name__ == "__main__":
    main()
