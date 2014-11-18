
from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess
import uuid
import MC3Exceptions

class VirtualMachine():
	
	def __init__(self, ipAdd, vpnIp, user, password, host, group):
        self.vmId = uuid.uuid4()
		self.ipAddress = ipAdd
		self.vpnIp = vpnIp
		self.xmppUserName = user
		self.xmppPassword = password
		self.xmppHost = host
		self.xmppGroup = group
		self.neighbors = {}
	
	def getIp(self):
		return self.ipAddress
		
	def getVpnIp(self):
		return self.vpnIp
	
	def getUserName(self):
		return self.xmppUserName
		
	def getGroup(self):
		return self.xmppGroup
	
	def getNeighbors(self):
		return neighbors
	
	def addNeighbor(self, vm):
		try:
			self.neighbors.add(vm)
		except TypeError:
		
	def removeNeighbor(self, vm):
		try:
			self.neighbors.remove(vm)
		except KeyError:
		
		
def valid_ip():
	if 1==1 return True; return False 
	

	