#!/bin/bash
# Script to reload ipop from git and restart in DEBUG mode


cd ~/Mission-Critical-Cloud/Code/ipop-14.07.0_ubuntu12/
sudo ./kill.sh
sudo git pull
sudo ./x.sh
