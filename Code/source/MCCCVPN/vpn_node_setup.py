'''
Script to download and install IPOP on this VM 
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


subprocess.Popen(["wget", "-O", "ipop-14.07.0_ubuntu12.tar.gz http://goo.gl/IsGzqI"])
subprocess.Popen(["tar", "xvzf", "ipop-14.07.0_ubuntu12.tar.gz"])
subprocess.Popen(["cd", "ipop-14.07.0_ubuntu12"])
