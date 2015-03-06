
#!/bin/bash
# Script to start ipop


cd ~/Mission-Critical-Cloud/ipop-14.07.0_ubuntu12/
sudo ./kill.sh
sudo sh -c './ipop-tincan-x86_64 1> out.log 2> err.log &'
sudo chmod 755 mcvpn_controller.py
sudo ./mcvpn_controller.py -c config.json & #> log.txt &
echo -e '\x02\x01{"m":"get_state"}' | netcat -q 1 -u 127.0.0.1 5800
sudo /sbin/ifconfig ipop
