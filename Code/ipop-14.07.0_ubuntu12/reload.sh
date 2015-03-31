#!/bin/bash
# Script to reload ipop from git and restart


cd ~/Mission-Critical-Cloud/Code/ipop-14.07.0_ubuntu12/
sudo ./kill.sh
sudo git pull
sudo ./start.sh
