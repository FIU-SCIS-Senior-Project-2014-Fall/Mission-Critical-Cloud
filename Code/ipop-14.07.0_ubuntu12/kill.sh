#!/bin/bash

ps -fa | grep ipop
sudo pkill ipop-tincan-x86_64
ps -fa | grep python
sudo pkill svpn_controller.py
sudo pkill gvpn_controller.py
sudo pkill mccvpn_controller.py
