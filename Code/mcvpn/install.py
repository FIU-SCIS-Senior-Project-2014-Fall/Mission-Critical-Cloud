#!/usr/bin/env python
from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess
import uuid


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
			"sudo service ejabberd restart",
			"sudo ejabberdctl register turing ejabberd pasword",
			"sudo ejabberdctl register dijkstra ejabberd pasword",
			"sudo ejabberdctl register knuth ejabberd pasword",			
			"sudo ejabberdctl register karp ejabberd pasword",
			"sudo ejabberdctl register hopcroft ejabberd pasword",
			"sudo ejabberdctl register tarjan ejabberd pasword",
			"sudo ejabberdctl register engelbart ejabberd pasword"
			"sudo ejabberdctl register rivest ejabberd pasword",
			"sudo ejabberdctl register shamir ejabberd pasword",
			"sudo ejabberdctl register adleman ejabberd pasword",
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
		subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT)

def main():	
	_run_cmd("mcc")
	_run_cmd("ejabberd")
	_run_cmd("ejabberd_init")    

if __name__ == "__main__":
    main()
