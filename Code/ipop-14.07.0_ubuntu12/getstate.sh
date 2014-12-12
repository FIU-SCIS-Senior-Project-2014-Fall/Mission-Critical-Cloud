#!/bin/bash

echo -e '\x02\x01{"m":"get_state"}' | netcat -q 1 -u 127.0.0.1 5800
/sbin/ifconfig ipop
