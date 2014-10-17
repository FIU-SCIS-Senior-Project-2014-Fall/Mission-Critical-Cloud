#!/usr/bin/env python

from __future__ import print_function
from pprint import pprint
import argparse
import os
import sys
import json
import subprocess
import uuid
import Path
import VirtualMachine

class VpnGroup():

	def __init__(self):
        self.vpnId = uuid.uuid4()
        self.members = {}
        self.paths = {}
        self.numMembers = 0
        self.active = False
	
	def getMembers(self):
		return self.members
		
	def addMember(self, vm):
		if vm not None:
			self.members.add(vm)
		else:
			raise TypeError
		
	def removeMember(self, vm):
		try:
			try:
				self.members.remove(vm)
			except KeyError:
				print "Virtual Machine not found in members set"
		except TypeError:
		
	def getPaths(self):
		return self.paths
	
	def addPath(self, path):
		if path not None:
			self.paths.add(path)
		else:
			raise TypeError

	def removePath(self, path):
		if path not None:
			try:
				self.paths.remove(path):
			except KeyError:
				print "Path not found in paths set."
		else:
			raise TypeError
				
	def isActive(self):
		return self.active
	
	def activate(self):
		if self.active == False:
			self.active = True
		else:
			raise Exception("This VPN Group is already Active")
			return False
	
	def deactivate(self):
		if self.active == True:
			self.active = False
		else:
			raise Exception("This VPN Group is already deactivated")
			return False
			
	def joinVpn(self, vm):
		try:
			addMember(vm)
		except TypeError:
		
	def leaveVpn(self, vm):
		try:
			removeMember(vm)
		except TypeError:
	
	