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

class Path():

	def __init__(self, delay, length, origin, destination, bidirectional):
        self.pathId = uuid.uuid4()
		self.delay = 0.0
		self.length = length
		self.origin = origin
		self.destination = destination
		self.bidirectional = bidirectional
		
	def getPathId(self):
		return self.pathId
		
	def getDelay(self):
		return self.delay
	
	def getLength(self):
		return self.length
	
	def getOrigin(self):
		return self.origin
	
	def getDestination(self):
		return self.destination
	
	def isBidirectional(self):
		return self.bidirectional
		
	def setDelay(self, delay):
		try:
			self.delay = delay
		except TypeError:
	
	def setLength(self, length):
		try:
			self.length = length
		except TypeError:
	
	
