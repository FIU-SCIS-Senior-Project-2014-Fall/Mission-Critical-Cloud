#!/bin/bash
# Script to reload ipop from git and restart


cd ~/Mission-Critical-Cloud/ipop-14.07.0_ubuntu12/
sudo ./kill.sh
sudo git pull
sudo ./x.sh