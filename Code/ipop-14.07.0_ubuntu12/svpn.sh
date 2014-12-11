#!/bin/bash
# Script to start ipop

cd ~/Mission-Critical-Cloud/ipop-14.07.0_ubuntu12/
sudo sh -c './ipop-tincan-x86_64 1> out.log 2> err.log &'
chmod 755 svpn_controller.py
./svpn_controller.py -c config.json &> log.txt &
echo -e '\x02\x01{"m":"get_state"}' | netcat -q 1 -u 127.0.0.1 5800
/sbin/ifconfig ipop
