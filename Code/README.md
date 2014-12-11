Mission-Critical-Cloud
======================

1.Introduction

This is the User Guide for the MC2 Service. This document provides basic installation, setup, and demonstration instructions to use the service. If you have any question please refer to the Accessing online help section of this document.

2.Hardware and Software Requirements
	Hardware
		1 personal computer for development, testing, and demos. Minimum requirements: Dual-core CPU @ 1.2 GHz, 2GB RAM, 128GB HDD.
		2+ servers where the cloud infrastructure will be set up. Minimum requirements: Dual-core CPU @ 1.4 GHz, 8GB RAM, 500 GB HDD, 2 x 1Gbps PCI LAN interfaces.
	Software
		OpenStack cloud computing platform.
		IPOP Peer to peer VPN networking controller
		Python 2.7
		Ubuntu Server 12.04 or 14.04 LTS.

3.Installation and Setup
    Begin by executing ./mcvpn.py on the desired physical host server.
        $ git clone https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git
        $ cd Mission-Critical-Cloud/mcvpn/
        $ ./mcvpn.py
    This command will download install and start the ejabberd service and install the xmpp server.
    Launch virtual machines as required within your Cloud Framework of choice i.e. OpenStack or Amazon AWS. 
    Once launched clone the Mission Critical Cloud files into the base directory of each virtual machine that will be a node member.  Once the git clone command completes change directory into the ipop-tincan folder
        $ git clone https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git
        $ cd ~/Mission-Critical-Cloud/ipop-14.07.0_ubuntu12/
    Run ./start.py to automatically run the MC^2 service the basic installation comes preconfigured to function properly and allows of virtual machines to self- discover.  You can change the default settings by editing the CONFIG.json file in the ipop directory.
        $ ./start.py
        
4.	Getting Started 

    To verify installation retrieve the IPV6 address of any of the virtual machine nodes that has the MC2 service running. 
        $ ./getstate.sh
    Copy the ipv6 address and use it to ping6 from another virtual machine in group.
        $
5.	Quick reference

6.	Accessing online help

    Go to the projects main website at mcc-dev.cis.fiu.edu to get help. Alternatively you can access the GitHub page as well.
    
7.	References

    MC^2 Homepage: mcc-dev.cis.fiu.edu
    Github:  https://github.com/FIU-SCIS-Senior-Project-2014-Fall/Mission-Critical-Cloud.git

