#!/usr/bin/env python

from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess
import uuid
import MC3Exceptions
import VirtualMachine

class XmppServer():
	
	def __init__(self, ipAdd, hostname, username, password):
        self.xmppId = uuid.uuid4()
		self.ipAddress = ipAdd
		self.hostname = hostname
		self.adminUser = user
		self.adminPassword = password
		self.virtualMachines = {}
		self.groups = {}
		
	def getIp(self):
		return self.ipAddress
		
	def getGroups(self):
		return self.groups
		
	def listVms(self):
		return self.virtualMachines
		
	def getHost(self):
		return self.hostname
	
	def getUserName(self):
		return self.adminUser
		
	def addVm(self, vm):
		try:
			self.virtualMachines.add(vm)
		except TypeError:
	
	def removeVm(self, vm):
		try:
			self.virtualMachines.remove(vm)
		except TypeError:
		
		
		
	
	
		
	