
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
import Path

import novaclient.v1_1.client as nvclient
from credentials import get_nova_creds


CONFIG = {"wait_time":60} #default is 1 minute

#TODO finish XMPPServer implementations
class XmppServer():

    def __init__(self, ipAdd, hostname, username, password):
        self.xmppId = uuid.uuid4()
        self.ipAddress = ipAdd
        self.hostname = hostname
        self.adminUser = user
        self.adminPassword = password
        self.virtualMachines = #this is Virtual Machine object
        self.groups = #this is a vpn group object

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



    def rpc(self, **params):
    '''initiates rpc call to server'''
    #TODO research good rpc call library
    #implement it here

    def get_vms(self):
    '''
    Returns data structure of virtual machines resident on this host 
    where this host servers as the XMPP server of our cloud neighbourhood
    '''

        creds = get_nova_creds()
        nova = nvclient.Client(**creds)
        #make call to Nova API to get virtual machines.
        #returns detailed list always
        return nova.servers.list(detailed=True)


    def parse_vms():
    #Perhaps this should be done in VirtualMachine.py
    '''
    Retrive and parse result of get_vms()'s nova api call
    since it will be in a different type of object
    this function should make it conform to the VirtualMachine 
    object specified in the class diagram and VirtualMachine.py
    '''

    def send_vms(self):
    '''
    Sends vm data to other vms
    global nieghbourhood update
    '''
        vms = get_vms()
        for vm in vms:
        rpc(vm.getIp, vms)

def main(self):
'''
Maintains data struct of active running vms and sends status 
update to cloud neighborhood via rpc call at specified
interval
'''
    #start XMPP server
    #check is ejabberd is running right now
    #"sudo ejabberdctl"
    #restart service
    #"sudo service restart ejabberd"
    count = 0
    last_time = time.time()
    while True:
    time_diff = time.time() - last_time
    if time_diff > CONFIG["wait_time"]: #default is 1 minute
    count += 1
    #thing to do
    send_vms()
    last_time = time.time()








