#!/usr/bin/env python

import argparse
import getpass
import hashlib
import json
import logging
import random
import select
import socket 
import struct
import sys
import time


# Set default config values
# default values should be those required for senior project demo
# unless otherwise specified.
CONFIG = {
	"xmpp_username": "",
    "xmpp_password": "",
    "xmpp_host": "",
    "stun": ,
    "turn": [],  # Contains dicts with "server", "user", "pass" keys
    "ip4": "172.16.0.1",
    "localhost": "127.0.0.1",
    "ip6_prefix": "fd50:0dbc:41f2:4a3c",
    "localhost6": "::1",
    "ip4_mask": 24,
    "ip6_mask": 64,
    "subnet_mask": 32,
    "svpn_port": 5800,
    "uid_size": 40,
    "sec": True,
    "wait_time": 15,
    "buf_size": 4096,
    "tincan_logging": 0,
    "controller_logging" : "INFO",
    "router_mode": False,
    "on-demand_connection" : True,
    "on-demand_inactive_timeout" : 600,
	"controller_logging": "DEBUG"
}