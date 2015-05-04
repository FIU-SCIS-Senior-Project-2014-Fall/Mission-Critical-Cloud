Mission-Critical-Cloud
======================

Introduction:

This is the User and Installation Guide for the MC2 Service. This document provides basic installation, setup, and demonstration instructions to use the service. If you have any question please refer to the Accessing online help section of this document.

Hardware and Software Requirements:

	Hardware:
	
		1 personal computer for development, testing, and demos. Minimum requirements: Dual-core CPU @ 1.2 GHz, 2GB RAM, 128GB HDD.
		2+ servers where the cloud infrastructure will be set up. Minimum requirements: Dual-core CPU @ 1.4 GHz, 8GB RAM, 500 GB HDD, 2 x 1Gbps PCI LAN interfaces.

	Software:
	
		OpenStack, Amazon EC2 or other cloud computing platform.
		IPOP Peer to peer VPN networking controller
    Ejabberd 2 XMPP Server
		Python 2.7
		Ubuntu Server 12.04 or 14.04 LTS.
		
Installation and Setup:

Begin by executing ./mcvpn.py on the desired physical host server.

	git clone https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git
	cd Mission-Critical-Cloud/mcvpn/
	./install.py
  
Alternatively you can follow the directions to install XMPP Server.

	https://github.com/ipop-project/documentation/wiki/Installing-XMPP-server
  
Run start.py to begin running XMPP server.
  cd Mission-Critical-Cloud/mcvpn/
	./start.py
	
This command will download install and start the ejabberd service and install the xmpp server.

Launch virtual machines as required within your Cloud Framework of choice i.e. OpenStack or Amazon AWS.
SSH into each virtual machine you have created.

Clone the Mission Critical Cloud files into the base directory of each virtual machine that will be a node member. Once the git clone command completes change directory into the ipop-tincan folder.
  
  1. git clone https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git
	2. cd ~/Mission-Critical-Cloud/ipop-14.07.0_ubuntu12
  
  3. Edit the config.json to specify the IP address of your XMPP server, give unique user names and IP addresses for each virtual machine you want in your cluster.
    {
      "xmpp_username": "namenode1@ejabberd", # <--- Unique User name *Choose one of the usernames that was setup for the XMPP server previously
      "xmpp_password": "password", # <--- Optional choose a good password *It's easier to test if you leave them all the same.
      "xmpp_host": "131.94.128.21", # <--- IP Address of XMPP Server
      "ip4": "172.31.x.y", #  <--- Choose Unique IP Address
      "ip4_mask": 24,
      "tincan_logging": 0,
      "controller_logging": "DEBUG"
    }

  4. Repeat the previous steps on all Virtual Machines that require the MCC servic
	
Run ./start.sh to automatically run the MC^2 service. The basic installation comes preconfigured to function properly and allows of virtual machines to self-discover.  You can change the default settings by editing the CONFIG.json file in the ipop directory.

	./start.sh
or
  ./x.sh
  
Alternatively run:
  
  ./reload.sh
or
  ./reload_debug.sh

To kill the service and pull the latest code from git hub and run the service silently or verbosely.


Stop/kill the service by executing:
  
  ./kill.sh

Getting Started:

To verify installation retrieve the IPV6 address of any of the virtual machine nodes that has the MC2 service running. 

	./getstate.sh
	
Once all machines have been setup and discovered each other use ping to verify connectivity.

Accessing online help : Go to the projects main website at mcc-dev.cis.fiu.edu to get help. Alternatively you can access the GitHub page as well.

References:

MC^2 Homepage: mcc-dev.cis.fiu.edu
Github:  https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git

