'''
Script to download and install XMPP services on the host machine
'''

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

def main():
	sp = subprocess.popen(["sudo", "apt-get", "update"])
	sp = subprocess.popen(["sudo", "apt-get", "install","ejabberd"])